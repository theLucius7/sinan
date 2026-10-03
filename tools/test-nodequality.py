#!/usr/bin/env python3
"""Verify capture, upload failure and report boundaries without running tests."""

import base64
import json
import hashlib
import importlib.util
import io
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
import os
import signal
import time
import stat
import threading
import shutil
from unittest import mock


sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nodequality_native_fixture_process import OwnedProcesses, group_has_live_members
PLUGIN = pathlib.Path(__file__).resolve().parent.parent / "plugins/nodequality"
FULL_START_GUARD = "[[ $mode != full ]] || die 'new full diagnostics are paused: complete tool provenance, redistribution rights, upload control and host side effects remain unverified'"
module_spec = importlib.util.spec_from_file_location("nodequality_report", PLUGIN / "report.py")
report = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(report)


def source_bundle():
    """Use private inert fixtures instead of downloading or running upstream."""
    lock = json.loads((PLUGIN / "source-lock.json").read_text())
    files = {}
    for row in lock["files"]:
        content = ("# Synthetic inert source fixture: " + row["name"] + "\n").encode()
        row["sha256"] = hashlib.sha256(content).hexdigest()
        row["size"] = len(content)
        files[row["name"]] = base64.b64encode(content).decode()
    return json.dumps(dict(schema=1, lock=lock, files=files)) + "\n"

# Verbatim post_cleanup from entrypoint a92fca6c, source SHA-256 4e1b2589...e0c018.
# Fixtures pad it to its real line 440; the normal terminal exit is line 455.
PINNED_POST_CLEANUP = '''function post_cleanup(){
    chroot_run umount -R /dev &> /dev/null
    clear_mount

    post_check_mount

    rm -rf $work_dir/BenchOs

    if [[ "$work_dir" == *"nodequality"* ]]; then
        rm -rf "${work_dir}"/
    else
        echo "$(L err01)"
        exit 1
    fi

    exit 1
}
'''


def make_archive(extra=None, missing=None, large=False):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, _ in report.SECTIONS:
            if name == missing:
                continue
            archive.writestr(name + ".log", "\x1b[31mActual " + name + " report\x1b[0m\n" + ("x" * 300000 if large else ""))
            if name != "header_info":
                archive.writestr(name + ".json", '{"Head":{"IP":"192.0.2.1"}}\n{"Head":{"IP":"2001:db8::1"}}\n')
        if extra is not None:
            archive.writestr(extra, "unexpected data")
    return target.getvalue()


class ReportTests(unittest.TestCase):
    def stage(self, directory, data):
        root = pathlib.Path(directory)
        (root / "upload.base64").write_bytes(base64.encodebytes(data))
        return root

    def test_complete_report_survives_failed_online_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            data = make_archive()
            root = self.stage(directory, data)
            (root / "upload-response.txt").write_text("Access denied")
            (root / "upload-status.txt").write_text("403")
            report.render(root)
            text = (root / "result.txt").read_text()
            self.assertIn("Actual ip_quality report", text)
            self.assertIn("本地报告已保留", text)
            self.assertIn("HTTP 状态：403", text)
            self.assertNotIn("\x1b", text)
            self.assertEqual((root / "report.zip").read_bytes(), data)
            self.assertFalse((root / "report-url.txt").exists())
            self.assertFalse((root / "upload.base64").exists())

    def test_online_url_requires_a_successful_http_status_and_exact_host(self):
        for response, status, expected in (
            ("测试完成：https://nodequality.com/r/abc-DEF_123\n", "200", True),
            ('{"url":"https://nodequality.com/r/abc-DEF_123"}', "200", True),
            ("https://nodequality.com/r/abc\n", "403", False),
            ("https://evil.example/r/abc\n", "200", False),
            ("https://nodequality.com/r/abc?redirect=evil\n", "200", False),
            ("https://nodequality.com/r/abc/extra\n", "200", False),
        ):
            with self.subTest(response=response, status=status):
                with tempfile.TemporaryDirectory() as directory:
                    root = self.stage(directory, make_archive())
                    (root / "upload-response.txt").write_text(response)
                    (root / "upload-status.txt").write_text(status)
                    report.render(root)
                    self.assertEqual((root / "report-url.txt").exists(), expected)

    def test_disabled_upload_keeps_the_report_local(self):
        with tempfile.TemporaryDirectory() as directory:
            data = make_archive()
            root = self.stage(directory, data)
            (root / "upload-disabled.txt").write_text("disabled\n")
            report.render(root)
            self.assertIn("公开报告上传已关闭", (root / "result.txt").read_text())
            self.assertEqual((root / "report.zip").read_bytes(), data)
            self.assertFalse((root / "report-url.txt").exists())

    def test_incomplete_report_is_not_published_as_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.stage(directory, make_archive(missing="net_quality"))
            with self.assertRaises(ValueError):
                report.render(root)
            self.assertFalse((root / "result.txt").exists())
            self.assertTrue((root / "report.zip").exists())

    def test_zip_paths_and_invalid_json_are_rejected(self):
        for filename in ("../result.txt", "/tmp/result.txt", "hardware_quality.log"):
            with self.subTest(path=filename):
                with tempfile.TemporaryDirectory() as directory:
                    root = self.stage(directory, make_archive(extra=filename))
                    with self.assertRaises(ValueError):
                        report.render(root)
                    self.assertFalse((root / "result.txt").exists())
        with self.assertRaises(ValueError):
            report.validate_json(b'{"Head": {}} trailing invalid data')
        with self.assertRaises(ValueError):
            report.validate_json(b'{}')

    def test_render_and_stream_limits_preserve_full_local_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            data = make_archive(large=True)
            root = self.stage(directory, data)
            report.render(root)
            self.assertLessEqual((root / "result.txt").stat().st_size, report.MAX_TEXT)
            self.assertEqual((root / "report.zip").read_bytes(), data)
            self.assertIn("完整原始结果", (root / "result.txt").read_text())
            subprocess.run([sys.executable, str(PLUGIN / "report.py"), "stream-log", str(root / "log.txt")],
                           input=b"a" * (report.MAX_TEXT + 100) + b"final failure", check=True)
            log = (root / "log.txt").read_bytes()
            self.assertEqual(len(log), report.MAX_TEXT)
            self.assertTrue(log.endswith(b"final failure"))

    def test_capture_rejects_oversized_input(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(PLUGIN / "report.py"), "capture", directory],
                                    input=b"a" * (report.MAX_CAPTURE + 1), capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((pathlib.Path(directory) / "upload.base64").exists())

    def test_chunked_upload_response_cannot_grow_the_output_file(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([sys.executable, str(PLUGIN / "report.py"), "response", directory],
                           input=b"x" * 100000 + b"\nSINAN_RESPONSE_STATUS:403", stdout=subprocess.DEVNULL, check=True)
            root = pathlib.Path(directory)
            self.assertEqual((root / "upload-response.txt").stat().st_size, 65536)
            self.assertEqual((root / "upload-status.txt").read_text(), "403")


class ChapterTests(unittest.TestCase):
    def stage(self, directory, data):
        root = pathlib.Path(directory)
        (root / "upload.base64").write_bytes(base64.encodebytes(data))
        return root

    def test_concurrent_atomic_writes_publish_whole_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / "section-header_info.json"
            barrier = threading.Barrier(2)
            fsync = report.os.fsync
            errors = []

            def synchronized_fsync(descriptor):
                if stat.S_ISREG(os.fstat(descriptor).st_mode):
                    barrier.wait(timeout=3)
                fsync(descriptor)

            def publish(data):
                try:
                    report.write_atomic(path, data)
                except Exception as error:
                    errors.append(error)

            with mock.patch.object(report.os, "fsync", side_effect=synchronized_fsync):
                writers = [threading.Thread(target=publish, args=(data,)) for data in (b"first", b"second")]
                for writer in writers:
                    writer.start()
                for writer in writers:
                    writer.join(timeout=5)
                    self.assertFalse(writer.is_alive())
            self.assertEqual(errors, [])
            self.assertIn(path.read_bytes(), (b"first", b"second"))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(list(root.glob(".section-header_info.json.*")), [])

    def test_concurrent_stale_preview_cannot_replace_a_completed_chapter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            report.save_section(root, "header_info", "initial preview", False)
            stale_read = threading.Event()
            release_stale = threading.Event()
            final_done = threading.Event()
            loads = report.json.loads
            errors = []

            def controlled_read(value, *args, **kwargs):
                previous = loads(value, *args, **kwargs)
                if threading.current_thread().name == "stale-preview":
                    stale_read.set()
                    if not release_stale.wait(timeout=3):
                        raise RuntimeError("preview writer was not released")
                return previous

            def publish(text, complete):
                try:
                    report.save_section(root, "header_info", text, complete)
                except Exception as error:
                    errors.append(error)
                finally:
                    if complete:
                        final_done.set()

            with mock.patch.object(report.json, "loads", side_effect=controlled_read):
                preview = threading.Thread(target=publish, name="stale-preview", args=("later preview", False))
                final = threading.Thread(target=publish, args=("completed original text", True))
                preview.start()
                self.assertTrue(stale_read.wait(timeout=3))
                final.start()
                # Without serialization the final write finishes before the stale
                # preview resumes, which deterministically regresses completion.
                final_done.wait(timeout=0.1)
                release_stale.set()
                for writer in (preview, final):
                    writer.join(timeout=5)
                    self.assertFalse(writer.is_alive())
            self.assertEqual(errors, [])
            saved = json.loads((root / "section-header_info.json").read_text())
            self.assertTrue(saved["complete"])
            self.assertEqual(saved["text"], "completed original text")
            self.assertGreater(saved["revision"], 1)

    def test_missing_chapter_preserves_the_other_four(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "upload.base64").write_bytes(base64.encodebytes(make_archive(missing="net_quality")))
            with self.assertRaises(ValueError):
                report.render(root)
            self.assertFalse((root / "result.txt").exists())
            chapters = list(root.glob("section-*.json"))
            self.assertEqual(len(chapters), 4)
            self.assertTrue(all(json.loads(path.read_text())["complete"] for path in chapters))
            self.assertIn("Actual ip_quality report", json.loads((root / "section-ip_quality.json").read_text())["text"])

    def test_invalid_saved_chapter_does_not_hide_other_archive_chapters(self):
        for content in ('{"unfinished":', '[]', '{"revision":true}'):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                data = make_archive()
                root = self.stage(directory, data)
                damaged = root / "section-hardware_quality.json"
                damaged.write_text(content)
                with self.assertRaisesRegex(ValueError, "hardware_quality"):
                    report.render(root)
                self.assertEqual(damaged.read_text(), content)
                self.assertEqual((root / "report.zip").read_bytes(), data)
                self.assertFalse((root / "result.txt").exists())
                for name, _ in report.SECTIONS:
                    if name != "hardware_quality":
                        chapter = json.loads((root / ("section-" + name + ".json")).read_text())
                        self.assertTrue(chapter["complete"])
                        self.assertIn("Actual " + name + " report", chapter["text"])

    def test_one_chapter_write_failure_preserves_others_and_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.stage(directory, make_archive())
            report.save_section(root, "hardware_quality", "saved preview", False)
            before = (root / "section-hardware_quality.json").read_bytes()
            write = report.write_atomic

            def fail_one(path, data):
                if path.name == "section-hardware_quality.json":
                    raise OSError("injected chapter write failure")
                write(path, data)

            with mock.patch.object(report, "write_atomic", side_effect=fail_one):
                with self.assertRaisesRegex(ValueError, "hardware_quality"):
                    report.render(root)
            self.assertEqual((root / "section-hardware_quality.json").read_bytes(), before)
            self.assertFalse((root / "result.txt").exists())
            saved = {}
            for name, _ in report.SECTIONS:
                if name != "hardware_quality":
                    path = root / ("section-" + name + ".json")
                    saved[name] = path.read_bytes()
                    self.assertTrue(json.loads(saved[name])["complete"])
            report.render(root)
            recovered = json.loads((root / "section-hardware_quality.json").read_text())
            self.assertTrue(recovered["complete"])
            self.assertEqual(recovered["revision"], 2)
            for name, content in saved.items():
                self.assertEqual((root / ("section-" + name + ".json")).read_bytes(), content)

    def test_invalid_saved_chapter_does_not_hide_live_sections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            live = root / ".nodequalityfixture/BenchOs/result"
            live.mkdir(parents=True)
            (root / "section-header_info.json").write_text("[]")
            (live / "header_info.log").write_text("real header")
            (live / "hardware_quality.log").write_text("completed hardware")
            (live / "hardware_quality.json").write_text('{"actual":true}')
            (live / "ip_quality.log").write_text("live IP preview")
            with self.assertRaisesRegex(ValueError, "header_info"):
                report.snapshot(root)
            hardware = json.loads((root / "section-hardware_quality.json").read_text())
            self.assertTrue(hardware["complete"])
            preview = json.loads((root / "section-ip_quality.json").read_text())
            self.assertFalse(preview["complete"])
            self.assertEqual(preview["text"], "live IP preview")

    def test_running_snapshots_survive_stop_and_monotonically_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            live = root / ".nodequalityfixture/BenchOs/result"
            live.mkdir(parents=True)
            (live / "header_info.log").write_text("real header")
            (live / "hardware_quality.log").write_text("hardware progress")
            report.snapshot(root)
            header = json.loads((root / "section-header_info.json").read_text())
            hardware = json.loads((root / "section-hardware_quality.json").read_text())
            self.assertTrue(header["complete"])
            self.assertFalse(hardware["complete"])
            self.assertEqual(hardware["revision"], 1)
            report.snapshot(root)
            self.assertEqual(json.loads((root / "section-hardware_quality.json").read_text())["revision"], 1)
            (live / "hardware_quality.json").write_text('{"actual":true}')
            (live / "ip_quality.log").write_text("next stage")
            report.snapshot(root)
            hardware = json.loads((root / "section-hardware_quality.json").read_text())
            self.assertTrue(hardware["complete"])
            self.assertEqual(hardware["revision"], 2)
            for path in live.iterdir():
                path.unlink()
            report.snapshot(root)
            self.assertEqual(json.loads((root / "section-hardware_quality.json").read_text()), hardware)

    def test_invalid_json_leaves_a_readable_incomplete_chapter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            live = root / ".nodequalityfixture/BenchOs/result"
            live.mkdir(parents=True)
            (live / "ip_quality.log").write_text("partial IP output")
            (live / "ip_quality.json").write_text('{"unfinished":')
            (live / "net_quality.log").write_text("next stage")
            report.snapshot(root)
            chapter = json.loads((root / "section-ip_quality.json").read_text())
            self.assertFalse(chapter["complete"])
            self.assertIn("partial IP", chapter["text"])

    def test_live_paths_do_not_follow_symlinks_or_oversize_files(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = pathlib.Path(directory)
            secret = pathlib.Path(outside)
            (secret / "header_info.log").write_text("private")
            live = root / ".nodequalityfixture/BenchOs/result"
            live.parent.mkdir(parents=True)
            live.symlink_to(secret, target_is_directory=True)
            report.snapshot(root)
            self.assertEqual(list(root.glob("section-*.json")), [])
            live.unlink()
            live.mkdir()
            (live / "header_info.log").symlink_to(secret / "header_info.log")
            (live / "hardware_quality.log").write_bytes(b"x" * (8 * 1024 * 1024 + 1))
            report.snapshot(root)
            self.assertEqual(list(root.glob("section-*.json")), [])

    def test_section_preview_is_bounded_without_destroying_the_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            data = make_archive(large=True)
            (root / "upload.base64").write_bytes(base64.encodebytes(data))
            report.render(root)
            self.assertEqual((root / "report.zip").read_bytes(), data)
            for path in root.glob("section-*.json"):
                chapter = json.loads(path.read_text())
                self.assertLessEqual(len(chapter["text"].encode()), report.MAX_SECTION)
                self.assertIn("章节文本已截断", chapter["text"])
                self.assertTrue(chapter["complete"])


class UploadPolicyTests(unittest.TestCase):
    def test_upload_never_calls_the_service_without_explicit_true(self):
        for option in (None, "false", "true", "yes"):
            with self.subTest(option=option):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    real = root / "real-curl"
                    real.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
root = pathlib.Path(os.environ["SINAN_REPORT_WORKSPACE"])
(root / "curl-called.txt").write_text("called")
sys.stdout.write("https://nodequality.com/r/fixture\\nSINAN_RESPONSE_STATUS:200")
''')
                    real.chmod(0o755)
                    environment = dict(os.environ)
                    environment.update(SINAN_REAL_CURL=str(real), SINAN_REPORT_WORKSPACE=directory,
                                       SINAN_REPORT_HELPER=str(PLUGIN / "report.py"))
                    environment.pop("SINAN_UPLOAD_REPORT", None)
                    if option is not None:
                        environment["SINAN_UPLOAD_REPORT"] = option
                    data = make_archive()
                    subprocess.run(["bash", str(PLUGIN / "curl-shim.sh"), "-X", "POST", "--data-binary", "@-",
                                    "https://api.nodequality.com/api/v1/record"],
                                   input=base64.b64encode(data), env=environment,
                                   capture_output=True, check=True)
                    self.assertEqual((root / "curl-called.txt").exists(), option == "true")
                    self.assertEqual((root / "upload-disabled.txt").exists(), option != "true")
                    report.render(root)
                    self.assertEqual((root / "report.zip").read_bytes(), data)
                    self.assertEqual((root / "report-url.txt").exists(), option == "true")


class BuildTests(unittest.TestCase):
    def test_failed_upstream_preserves_complete_outputs_without_reporting_success(self):
        for exit_code in (0, 1, 7):
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                workspace = root / "workspace"
                workspace.mkdir(mode=0o700)
                binaries = root / "bin"
                binaries.mkdir()
                for name in ("uname", "curl", "tar", "base64", "mount", "umount", "mountpoint", "chroot"):
                    tool = binaries / name
                    tool.write_text("#!/bin/sh\nprintf 'Linux\\n'\n" if name == "uname" else "#!/bin/sh\nexit 0\n")
                    tool.chmod(0o700)
                archive = make_archive()
                upstream = ('python3 "$SINAN_REPORT_HELPER" capture "$SINAN_REPORT_WORKSPACE" <<\'ARCHIVE\'\n'
                            + base64.b64encode(archive).decode() + '\nARCHIVE\nexit ' + str(exit_code) + '\n')
                runner = (PLUGIN / "runner.sh.tmpl").read_text()
                # This private inert collector fixture retains old recovery
                # coverage; the production template has no bypass option.
                self.assertEqual(runner.count(FULL_START_GUARD), 1)
                runner = runner.replace(FULL_START_GUARD, ":")
                # The fixture executes no hardware, mounts or network operations;
                # exercise the exact wrapper on macOS without requiring real root.
                for requirement in ("[[ $EUID == 0 ]] || die 'diagnostics require root'",
                                    "[[ ${BASH_VERSINFO[0]} -ge 4 ]] || die 'diagnostics require Bash >= 4'"):
                    self.assertEqual(runner.count(requirement), 1)
                    runner = runner.replace(requirement, ":")
                for marker, source in (("@NODEQUALITY_SOURCE@", upstream), ("@NODEQUALITY_LICENSE@", "fixture"),
                                       ("@SOURCE_HELPER@", (PLUGIN / "source-helper.py").read_text()),
                                       ("@REPORT_POLICY_HELPER@", (PLUGIN / "report-policy.py").read_text()),
                                       ("@SWAP_POLICY_HELPER@", (PLUGIN / "swap-policy.py").read_text()),
                                       ("@DEPENDENCY_POLICY_HELPER@", (PLUGIN / "dependency-policy.py").read_text()),
                                       ("@DATA_POLICY_HELPER@", (PLUGIN / "data-policy.py").read_text()),
                                       ("@LOADER_POLICY_HELPER@", (PLUGIN / "loader-policy.py").read_text()),
                                       ("@RANKING_POLICY_HELPER@", (PLUGIN / "ranking-policy.py").read_text()),
                                       ("@IP_SCORE_POLICY_HELPER@", (PLUGIN / "ip-score-policy.py").read_text()),
                                       ("@NETFLIX_POLICY_HELPER@", (PLUGIN / "netflix-policy.py").read_text()),
                                       ("@BROWSER_POLICY_HELPER@", (PLUGIN / "browser-policy.py").read_text()),
                                       ("@PUBLIC_ACCESS_POLICY_HELPER@", (PLUGIN / "public-access-policy.py").read_text()),
                                       ("@PINNED_CHAIN@", source_bundle()),
                                       ("@REPORT_HELPER@", (PLUGIN / "report.py").read_text()),
                                       ("@EXIT_OBSERVER@", (PLUGIN / "exit-observer.sh").read_text()),
                                       ("@DAILY_HELPER@", (PLUGIN / "daily.py").read_text()),
                                       ("@OFFICIAL_IP_HELPER@", (PLUGIN / "official-ip.py").read_text()),
                                       ("@EXECUTION_ADMISSION@", (PLUGIN / "execution-admission.json").read_text()),
                                       ("@CURL_SHIM@", (PLUGIN / "runtime-curl.sh").read_text()),
                                       ("@CHROOT_SHIM@", (PLUGIN / "chroot-shim.sh").read_text())):
                    runner = runner.replace(marker, source)
                executable = root / "nodequality"
                executable.write_text(runner)
                owned = OwnedProcesses(root)
                result = owned.run(["bash", str(executable), "--workspace", str(workspace), "--ip-version", "ipv4"],
                                   env=dict(os.environ, PATH=str(binaries) + ":" + os.environ["PATH"]),
                                   capture_output=True, text=True, timeout=15)
                self.assertEqual((workspace / "upstream-exit.txt").read_text().strip(), str(exit_code),
                                 (result.stdout, result.stderr, (workspace / "log.txt").read_text()))
                self.assertEqual((workspace / "report.zip").read_bytes(), archive)
                self.assertIn("Actual hardware_quality report", (workspace / "result.txt").read_text())
                self.assertEqual(len(list(workspace.glob("section-*.json"))), 5)
                self.assertEqual(result.returncode, exit_code)

    def test_repeated_build_refuses_to_modify_the_existing_artifact_and_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            version = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r22"
            root = pathlib.Path(directory) / "nodequality" / version
            root.mkdir(parents=True)
            artifact = root / "amd64"
            content = b"already verified artifact"
            artifact.write_bytes(content)
            manifest = root / "SHA256SUMS"
            checksum = hashlib.sha256(content).hexdigest() + "  amd64\n"
            manifest.write_text(checksum)
            result = subprocess.run(["bash", str(PLUGIN.parents[1] / "tools/build-nodequality.sh"), "amd64", directory],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("immutable artifact already exists", result.stderr)
            self.assertEqual(artifact.read_bytes(), content)
            self.assertEqual(manifest.read_text(), checksum)
            self.assertFalse((root / ".build.lock").exists())
    def test_retained_trace_installation_is_refused_in_both_architectures(self):
        fixed = "wget https://github.com/nxtrace/NTrace-core/releases/download/v1.3.7/nexttrace_linux_amd64 -qO /usr/local/bin/nexttrace"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            real = root / "real-chroot"
            real.write_text('#!/usr/bin/env python3\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n')
            real.chmod(0o755)
            fake_uname = root / "uname"
            for arch in ("x86_64", "aarch64", "arm64"):
                fake_uname.write_text("#!/bin/sh\nprintf '%s\\n' '" + arch + "'\n")
                fake_uname.chmod(0o755)
                environment = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"], SINAN_REAL_CHROOT=str(real))
                for command in (fixed, fixed.replace('nexttrace_linux_amd64', 'nexttrace_linux_arm64'), "printf ordinary-command"):
                    with self.subTest(arch=arch, command=command):
                        result = subprocess.run(["bash", str(PLUGIN / "chroot-shim.sh"), "/fixture/BenchOs", "/bin/bash", "-c", command],
                                                env=environment, capture_output=True, text=True)
                        if 'wget ' in command:
                            self.assertEqual(result.returncode, 70)
                            self.assertIn('online trace installation is forbidden', result.stderr)
                            self.assertEqual(result.stdout, '')
                        else:
                            self.assertEqual(result.returncode, 0)
                            self.assertEqual(report.json.loads(result.stdout), ["/fixture/BenchOs", "/bin/bash", "-c", command])

    def test_runner_rejects_workspace_expansion_before_starting_any_test(self):
        for directory in ("/tmp/space path", "/tmp/wild*card", "/tmp/question?mark", "/tmp/bracket[1]"):
            with self.subTest(directory=directory):
                result = subprocess.run(["bash", str(PLUGIN / "runner.sh.tmpl"), "--workspace", directory],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("workspace must not contain whitespace or shell glob", result.stderr)

    def test_runner_rejects_ambiguous_upload_options_before_starting(self):
        for option in ("yes", "1", "", "$(id)"):
            with self.subTest(option=option):
                result = subprocess.run(["bash", str(PLUGIN / "runner.sh.tmpl"), "--workspace", "/tmp/fixture",
                                         "--upload-report", option], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid report upload option", result.stderr)

    def test_unmodified_runner_refuses_explicit_and_default_full_before_any_external_call_or_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            binary = root / 'bin'
            binary.mkdir()
            called = root / 'called'
            for name in ('uname', 'python3', 'curl', 'mkdir', 'mount', 'chroot', 'rm', 'umount'):
                tool = binary / name
                tool.write_text('#!/bin/sh\nprintf called > "$NQ_CALLED"\nexit 99\n')
                tool.chmod(0o700)
            environment = dict(os.environ, PATH=str(binary), NQ_CALLED=str(called))
            for options in ([], ['--mode', 'full'], ['--mode', 'full', '--upload-report', 'true']):
                workspace = root / 'not-created'
                result = subprocess.run([shutil.which('bash'), str(PLUGIN / 'runner.sh.tmpl'),
                                         '--workspace', str(workspace)] + options,
                                        env=environment, capture_output=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'new full diagnostics are paused', result.stderr)
                self.assertFalse(called.exists())
                self.assertFalse(workspace.exists())

    def test_shell_syntax_and_nonexecuting_help(self):
        for script in (PLUGIN / "runner.sh.tmpl", PLUGIN / "exit-observer.sh", PLUGIN / "curl-shim.sh", PLUGIN / "runtime-curl.sh", PLUGIN / "chroot-shim.sh", PLUGIN.parents[1] / "tools/build-nodequality.sh"):
            subprocess.run(["bash", "-n", str(script)], check=True)
        result = subprocess.run(["bash", str(PLUGIN / "runner.sh.tmpl"), "--version"],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "nodequality a92fca6c0067df29ddd03fdc2fee6f3000f64545-r22")

    def test_existing_architecture_checksums_are_not_replaced(self):
        script = (PLUGIN.parents[1] / "tools/build-nodequality.sh").read_text()
        source = script.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        for state in ("empty", "valid", "tampered", "missing-sum", "missing-file", "duplicate", "symlink"):
            with self.subTest(state=state):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    payload = b"previous pinned artifact"
                    digest = hashlib.sha256(payload).hexdigest()
                    artifact = root / "amd64"
                    manifest = root / "SHA256SUMS"
                    if state != "empty":
                        artifact.write_bytes(payload)
                        manifest.write_text(digest + "  amd64\n")
                    if state == "tampered":
                        artifact.write_bytes(b"changed")
                    elif state == "missing-sum":
                        manifest.unlink()
                    elif state == "missing-file":
                        artifact.unlink()
                    elif state == "duplicate":
                        manifest.write_text((digest + "  amd64\n") * 2)
                    elif state == "symlink":
                        artifact.rename(root / "original")
                        artifact.symlink_to(root / "original")
                    result = subprocess.run([sys.executable, "-", directory], input=source,
                                            text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, state in ("empty", "valid"), result.stderr)


class RunnerFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sinan-nodequality-runner-fixture-")
        self.root = pathlib.Path(self.temporary.name)
        self.processes = OwnedProcesses(self.root)
        self.addCleanup(self.processes.cleanup_temporary, self.temporary, self)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.binary = self.root / "bin"
        self.binary.mkdir()
        self.emulated_guards = not (sys.platform.startswith("linux") and os.geteuid() == 0)
        if not sys.platform.startswith("linux"):
            self.stub("uname", "#!/bin/sh\nprintf 'Linux\\n'\n")
        for name in ("mount", "chroot"):
            self.stub(name, "#!/bin/sh\nexit 0\n")
        self.stub("mountpoint", "#!/bin/sh\nexit 1\n")
        self.stub("umount", '#!/bin/sh\nprintf "%s\\n" "$*" >> "$NQ_FIXTURE_ROOT/cleanup.txt"\n')
        self.stub("curl", '''#!/usr/bin/env python3
import os, pathlib, sys
(pathlib.Path(os.environ["NQ_FIXTURE_ROOT"]) / "curl-called.txt").write_text("called")
sys.stdout.write(os.environ["NQ_FIXTURE_RESPONSE"] + "\\nSINAN_RESPONSE_STATUS:" + os.environ["NQ_FIXTURE_STATUS"])
raise SystemExit(int(os.environ.get("NQ_FIXTURE_CURL_EXIT", "0")))
''')
        self.environment = dict(os.environ)
        self.environment.update({
            "PATH": str(self.binary) + ":" + os.environ["PATH"],
            "NQ_FIXTURE_ROOT": str(self.root),
            "NQ_FIXTURE_RESPONSE": "测试完成：https://nodequality.com/r/fixture_REPORT-123\n",
            "NQ_FIXTURE_STATUS": "200",
        })

    def stub(self, name, source):
        target = self.binary / name
        target.write_text(source)
        target.chmod(0o755)

    def runner(self, mode="report"):
        fixture = '''#!/usr/bin/env bash
set -uo pipefail
chroot_run(){ :; }
clear_mount(){ :; }
post_check_mount(){ :; }
sig_cleanup(){ trap '' INT TERM SIGHUP EXIT; post_cleanup; }
main(){
while [[ $# != 0 ]]; do
  case "$1" in -d) workspace=$2; shift 2 ;; -4|-6) ip=$1; shift ;; *) exit 5 ;; esac
done
read -r hardware; read -r ip_test; read -r network; read -r trace
printf '%s/%s/%s/%s/%s\\n' "$hardware" "$ip_test" "$network" "$trace" "${ip:-both}" > "$workspace/fixture-options.txt"
mkdir -p "$workspace/.nodequalityfixture/BenchOs/dev" "$workspace/.nodequalityfixture/BenchOs/sys" "$workspace/.nodequalityfixture/BenchOs/proc"
work_dir=$workspace/.nodequalityfixture
'''
        if mode == "report":
            # Match the pinned main's EXIT trap as well as its terminal branch.
            fixture += "trap 'sig_cleanup' INT TERM SIGHUP EXIT\n"
        if mode in ("report", "success", "nonzero", "failed", "early-one", "signal-cleanup", "cleanup-refused"):
            self.fixture_archive = make_archive()
            encoded = base64.b64encode(self.fixture_archive).decode()
            fixture += "printf '%s' '" + encoded + "' | curl -X POST --data-binary @- https://api.nodequality.com/api/v1/record\n"
            fixture += {
                "report": "post_cleanup\n",
                "success": "exit 0\n",
                "nonzero": "exit 1\n",
                "failed": "exit 7\n",
                "early-one": "exit 1\n",
                "signal-cleanup": "sig_cleanup\n",
                "cleanup-refused": "post_check_mount(){ exit 1; }\npost_cleanup\n",
            }[mode]
        elif mode == "sleep":
            fixture += 'touch "$workspace/fixture-ready"\nsleep 30\nexit 1\n'
        elif mode == "missing-reports":
            fixture += "post_cleanup\n"
        else:
            fixture += "printf 'no actual reports were produced\\n'\nexit 0\n"
        fixture += "}\n"
        fixture += "\n" * (439 - len(fixture.splitlines())) + PINNED_POST_CLEANUP + "main \"$@\"\n"
        self.assertEqual(fixture.splitlines()[454], "    exit 1")
        content = (PLUGIN / "runner.sh.tmpl").read_text()
        self.assertEqual(content.count(FULL_START_GUARD), 1)
        content = content.replace(FULL_START_GUARD, ':')
        # Mounts, chroot and networking are always fake. Outside Linux/root only
        # the fixture copy bypasses entry guards; native CI keeps them unchanged.
        if self.emulated_guards:
            for guard in ("[[ $EUID == 0 ]] || die 'diagnostics require root'",
                          "[[ ${BASH_VERSINFO[0]} -ge 4 ]] || die 'diagnostics require Bash >= 4'"):
                self.assertEqual(content.count(guard), 1)
                content = content.replace(guard, ":")
        for marker, payload in (
            ("NODEQUALITY_SOURCE", fixture),
            ("NODEQUALITY_LICENSE", "Synthetic test fixture; no upstream tests run.\n"),
            ("SOURCE_HELPER", (PLUGIN / "source-helper.py").read_text()),
            ("REPORT_POLICY_HELPER", (PLUGIN / "report-policy.py").read_text()),
            ("SWAP_POLICY_HELPER", (PLUGIN / "swap-policy.py").read_text()),
            ("DEPENDENCY_POLICY_HELPER", (PLUGIN / "dependency-policy.py").read_text()),
            ("DATA_POLICY_HELPER", (PLUGIN / "data-policy.py").read_text()),
            ("LOADER_POLICY_HELPER", (PLUGIN / "loader-policy.py").read_text()),
            ("RANKING_POLICY_HELPER", (PLUGIN / "ranking-policy.py").read_text()),
            ("IP_SCORE_POLICY_HELPER", (PLUGIN / "ip-score-policy.py").read_text()),
            ("NETFLIX_POLICY_HELPER", (PLUGIN / "netflix-policy.py").read_text()),
            ("BROWSER_POLICY_HELPER", (PLUGIN / "browser-policy.py").read_text()),
            ("PUBLIC_ACCESS_POLICY_HELPER", (PLUGIN / "public-access-policy.py").read_text()),
            ("PINNED_CHAIN", source_bundle()),
            ("REPORT_HELPER", (PLUGIN / "report.py").read_text()),
            ("EXIT_OBSERVER", (PLUGIN / "exit-observer.sh").read_text()),
            ("DAILY_HELPER", (PLUGIN / "daily.py").read_text()),
            ("OFFICIAL_IP_HELPER", (PLUGIN / "official-ip.py").read_text()),
            ("EXECUTION_ADMISSION", (PLUGIN / "execution-admission.json").read_text()),
            ("CURL_SHIM", (PLUGIN / "runtime-curl.sh").read_text()),
            ("CHROOT_SHIM", (PLUGIN / "chroot-shim.sh").read_text()),
        ):
            content = content.replace("@" + marker + "@\n", payload)
        path = self.root / "nodequality"
        path.write_text(content)
        path.chmod(0o755)
        return ["bash", str(path), "--workspace", str(self.workspace),
                "--ip-version", "ipv6", "--network-mode", "low"]

    def assert_complete_runner_report(self, mode, upstream_status, status):
        result = self.processes.run(self.runner(mode) + ["--mode", "full"], env=self.environment, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, status, result.stderr.decode())
        self.assertEqual((self.workspace / "upstream-exit.txt").read_text().strip(), str(upstream_status))
        self.assertEqual((self.workspace / "fixture-options.txt").read_text().strip(), "y/y/l/y/-6")
        text = (self.workspace / "result.txt").read_text()
        for name, _ in report.SECTIONS:
            self.assertIn("Actual " + name + " report", text)
        self.assertEqual((self.workspace / "report.zip").read_bytes(), self.fixture_archive)
        self.assertIn("公开报告上传已关闭", text)
        self.assertFalse((self.workspace / "report-url.txt").exists())
        self.assertFalse((self.root / "curl-called.txt").exists())
        self.assertFalse((self.workspace / ".nodequalityfixture").exists())
        self.assertFalse((self.workspace / ".runner").exists())

    def test_pinned_cleanup_exit_one_still_requires_four_actual_local_reports(self):
        self.assert_complete_runner_report("report", 1, 0)

    def test_upstream_nonzero_exit_still_requires_four_actual_local_reports(self):
        # Preserve the raw success/failure distinction introduced by PR #56.
        for mode, status in (("success", 0), ("nonzero", 1)):
            with self.subTest(mode=mode):
                self.assert_complete_runner_report(mode, status, status)
                for path in self.workspace.iterdir():
                    path.unlink()

    def test_explicit_upload_true_produces_the_online_report(self):
        result = self.processes.run(self.runner() + ["--upload-report", "true"], env=self.environment,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.workspace / "report-url.txt").read_text().strip(),
                         "https://nodequality.com/r/fixture_REPORT-123")
        self.assertTrue((self.root / "curl-called.txt").exists())

    def test_upload_403_preserves_a_complete_local_report(self):
        self.environment.update(NQ_FIXTURE_STATUS="403", NQ_FIXTURE_RESPONSE="Access denied",
                                NQ_FIXTURE_CURL_EXIT="22")
        result = self.processes.run(self.runner() + ["--upload-report", "true"], env=self.environment,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn("HTTP 状态：403", (self.workspace / "result.txt").read_text())
        self.assertFalse((self.workspace / "report-url.txt").exists())
        self.assertTrue((self.workspace / "report.zip").is_file())

    def test_upload_transport_failure_is_separate_from_upstream_execution_failure(self):
        self.environment.update(NQ_FIXTURE_STATUS="000", NQ_FIXTURE_RESPONSE="Fixture connection failed",
                                NQ_FIXTURE_CURL_EXIT="7")
        result = self.processes.run(self.runner() + ["--upload-report", "true"], env=self.environment,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.workspace / "upstream-exit.txt").read_text().strip(), "1")
        self.assertIn("HTTP 状态：000", (self.workspace / "result.txt").read_text())
        self.assertFalse((self.workspace / "report-url.txt").exists())
        self.assertEqual((self.workspace / "report.zip").read_bytes(), self.fixture_archive)
        self.assertEqual(len(list(self.workspace.glob("section-*.json"))), 5)

    def test_unproven_exit_one_and_genuine_exit_seven_never_report_success(self):
        for mode, status in (("early-one", 1), ("failed", 7)):
            with self.subTest(mode=mode):
                try:
                    result = self.processes.run(self.runner(mode), env=self.environment, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, status, result.stderr.decode())
                    self.assertEqual((self.workspace / "upstream-exit.txt").read_text().strip(), str(status))
                    self.assertTrue((self.workspace / "result.txt").is_file())
                    self.assertEqual((self.workspace / "report.zip").read_bytes(), self.fixture_archive)
                    self.assertEqual(len(list(self.workspace.glob("section-*.json"))), 5)
                finally:
                    for path in self.workspace.iterdir():
                        path.unlink()

    def test_signal_cleanup_cannot_prove_normal_completion(self):
        result = self.processes.run(self.runner("signal-cleanup"), env=self.environment,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr.decode())
        self.assertTrue((self.workspace / "result.txt").is_file())
        self.assertEqual((self.workspace / "report.zip").read_bytes(), self.fixture_archive)

    def test_cleanup_refusal_cannot_prove_normal_completion(self):
        result = self.processes.run(self.runner("cleanup-refused"), env=self.environment,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr.decode())
        self.assertTrue((self.workspace / "result.txt").is_file())
        self.assertEqual((self.workspace / "report.zip").read_bytes(), self.fixture_archive)

    def test_zero_exit_or_normal_cleanup_without_a_zip_is_failed(self):
        for mode in ("empty", "missing-reports"):
            with self.subTest(mode=mode):
                result = self.processes.run(self.runner(mode), env=self.environment, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.workspace / "result.txt").exists())
                self.assertIn(b"a complete local NodeQuality report was not produced", result.stderr)
                for path in self.workspace.iterdir():
                    path.unlink()

    def test_daily_branch_never_runs_upstream_or_creates_mounts(self):
        targets = self.workspace / "daily-targets.json"
        targets.write_text("[]")
        result = self.processes.run(self.runner("sleep") + ["--mode", "daily", "--targets-file", str(targets)],
                                env=self.environment, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.workspace / "section-net_quality.json").exists())
        self.assertFalse((self.workspace / "fixture-ready").exists())
        self.assertFalse((self.workspace / "report.zip").exists())
        self.assertFalse((self.workspace / "upstream-exit.txt").exists())
        self.assertFalse((self.workspace / ".runner").exists())
        self.assertFalse((self.workspace / ".runner.lock").exists())
        self.assertFalse((self.root / "cleanup.txt").exists())

    def test_signal_cleans_only_the_private_workspace(self):
        child = self.processes.spawn(self.runner("sleep"), env=self.environment)
        process = child.process
        try:
            deadline = time.monotonic() + 5
            while not (self.workspace / "fixture-ready").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue((self.workspace / "fixture-ready").exists())
            os.killpg(process.pid, signal.SIGTERM)
            child.collect(timeout=5)
        finally:
            self.processes.stop(child)
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse((self.workspace / ".nodequalityfixture").exists())
        self.assertFalse((self.workspace / ".runner.lock").exists())
        cleanup = (self.root / "cleanup.txt").read_text().splitlines()
        self.assertEqual(len(cleanup), 3)
        self.assertTrue(all(str(self.workspace) in call for call in cleanup))

    def test_fixture_timeout_confirms_owned_descendants_and_keeps_external_sentinel_alive(self):
        sentinel = self.processes.spawn([sys.executable, "-B", "-c", "import time;time.sleep(30)"])
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.processes.run(self.runner("sleep"), env=self.environment, timeout=2)
            wrapper = self.processes.children[-1]
            self.assertTrue(wrapper.cleanup_confirmed)
            self.assertFalse(group_has_live_members(wrapper.pid))
            self.assertIsNone(sentinel.process.poll())
        finally:
            self.processes.stop(sentinel)

    def test_fixture_exception_after_spawn_confirms_owned_group_cleanup(self):
        def cancelled(_child):
            if (self.workspace / "fixture-ready").exists():
                raise RuntimeError("TEST_ONLY outer fixture cancellation")

        with self.assertRaisesRegex(RuntimeError, "outer fixture cancellation"):
            self.processes.run(self.runner("sleep"), env=self.environment, timeout=5, guard=cancelled)
        wrapper = self.processes.children[-1]
        self.assertTrue(wrapper.cleanup_confirmed)
        self.assertFalse(group_has_live_members(wrapper.pid))

    @unittest.skipUnless(sys.platform == "linux", "direct child identity is observed through Linux procfs")
    def test_killed_wrapper_collector_exits_before_owned_group_cleanup(self):
        sentinel = self.processes.spawn([sys.executable, "-B", "-c", "import time;time.sleep(30)"])
        child = self.processes.spawn(self.runner("sleep"), env=self.environment)
        watcher = None

        def direct_children():
            # task/<pid>/children is optional in Linux kernels. Enumerate only
            # bounded PID/parent metadata, then inspect exact owned candidates.
            observed = self.processes.run(["/bin/ps", "-axo", "pid=,ppid="], timeout=2,
                                         env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            if observed.returncode or observed.stderr or len(observed.stdout) > 128 * 1024:
                raise RuntimeError("owned child parent metadata observation failed or exceeded its limit")
            rows = observed.stdout.decode("ascii").splitlines()
            if len(rows) > 8192:
                raise RuntimeError("owned child parent metadata exceeded its row limit")
            children = []
            for row in rows:
                fields = row.split()
                if len(fields) != 2 or not all(field.isdigit() for field in fields):
                    raise RuntimeError("owned child parent metadata has an invalid shape")
                if int(fields[1]) == child.pid:
                    children.append(int(fields[0]))
            return children

        def identity(pid):
            try:
                fields = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
                if fields[0] == "Z":
                    return None
                return fields[19], pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
            except FileNotFoundError:
                return None

        try:
            deadline = time.monotonic() + 5
            expected = [str(self.workspace / ".runner/report.py").encode(), b"watch-sections",
                        str(self.workspace).encode(), str(child.pid).encode()]
            while time.monotonic() < deadline:
                for pid in direct_children():
                    observed = identity(pid)
                    if observed is not None and observed[1].rstrip(b"\0").split(b"\0")[1:] == expected:
                        watcher = pid, observed
                        break
                if watcher is not None and (self.workspace / "fixture-ready").exists():
                    break
                child.read_ready(0.02)
            self.assertIsNotNone(watcher, "actual private collector never executed")
            self.assertTrue((self.workspace / "fixture-ready").exists())
            child.process.kill()
            child.process.wait(timeout=2)
            deadline = time.monotonic() + 3
            while identity(watcher[0]) == watcher[1] and time.monotonic() < deadline:
                child.read_ready(0.03)
            self.assertNotEqual(identity(watcher[0]), watcher[1], "collector survived its actual parent")
            # The inert upstream intentionally still sleeps. The watcher must
            # stop itself before fixture cleanup signals any remaining group.
            self.assertTrue(group_has_live_members(child.pid))
            self.assertIsNone(sentinel.process.poll())
        finally:
            try:
                self.processes.stop(child)
            finally:
                self.processes.stop(sentinel)


if __name__ == "__main__":
    unittest.main()
