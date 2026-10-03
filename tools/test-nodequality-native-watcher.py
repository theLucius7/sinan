#!/usr/bin/env python3
"""Real watcher ownership regressions; no benchmark or hardware test is run."""
import base64
import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import unittest
import zipfile
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from nodequality_native_fixture_process import ObservedProcess, group_has_live_members

REPORT = ROOT / "plugins/nodequality/native-report.py"
MAX_LOG = 128 * 1024
WAIT_SECONDS = 6


def interpreter_image():
    """Choose an image from our interpreter metadata, never a child's argv."""
    executable = Path(sys.executable).resolve(strict=True)
    image = executable
    framework = sysconfig.get_config_var("PYTHONFRAMEWORK")
    if sys.platform == "darwin" and framework:
        prefix = sysconfig.get_config_var("PYTHONFRAMEWORKINSTALLNAMEPREFIX")
        if (not isinstance(framework, str) or not framework.isascii() or not framework.isidentifier()
                or not isinstance(prefix, str) or not Path(prefix).is_absolute()):
            raise RuntimeError("trusted framework interpreter metadata differs")
        version = Path(prefix).resolve(strict=True)
        image = version / "Resources" / (framework + ".app") / "Contents" / "MacOS" / framework
        if executable != image and executable.parent != version / "bin":
            raise RuntimeError("current interpreter is outside its trusted framework")
    info = image.lstat()
    if not stat.S_ISREG(info.st_mode) or not os.access(image, os.X_OK):
        raise RuntimeError("trusted interpreter image is not an ordinary executable")
    return str(image)


INTERPRETER = interpreter_image()


def private_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        # Publish complete readiness/evidence bytes without replacing old evidence.
        os.link(temporary, path)
    finally:
        temporary.unlink()


def pid_observation(pid):
    """Observe the owned child's parent and exact command before binding it."""
    result = subprocess.run(["/bin/ps", "-ww", "-o", "ppid=,stat=,lstart=,command=", "-p", str(pid)],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=2,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    if len(result.stdout) + len(result.stderr) > 16384:
        raise RuntimeError("owned PID observation exceeded its output budget")
    if result.returncode not in (0, 1):
        raise RuntimeError("owned PID observation failed")
    fields = result.stdout.decode("utf-8", errors="strict").split(None, 7)
    # An orphan zombie has exited; this test cannot reap another PID's child.
    if not fields or len(fields) >= 2 and fields[1].startswith("Z"):
        return None
    if len(fields) != 8 or not fields[0].isdigit():
        raise RuntimeError("owned PID observation has an invalid shape")
    try:
        return {"parent_pid": int(fields[0]), "state": fields[1],
                "identity": (" ".join(fields[2:7]), fields[7].strip(), os.getpgid(pid), os.getsid(pid))}
    except ProcessLookupError:
        return None


def pid_identity(pid):
    """Orphan liveness keeps start/argv/group identity as its parent changes."""
    observed = pid_observation(pid)
    return None if observed is None else observed["identity"]


def directory_identity(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("owned readiness directory is not ordinary")
    return info.st_dev, info.st_ino


def readiness_probe(row, expected_command, workspace, directory_ids):
    samples = row["readiness_samples"]
    if len(samples) >= 64:
        raise RuntimeError("owned readiness identity sample limit exceeded")
    observed = pid_observation(row["watcher_pid"])
    sample = {"elapsed_monotonic": time.monotonic() - row["readiness_started"],
              "observation": observed, "reason": "pending"}
    samples.append(sample)
    try:
        if row["process"].poll() is not None:
            raise RuntimeError("actual direct owner exited before watcher readiness")
        if observed is None or (row["directory"] / "watcher-exit.json").exists():
            raise RuntimeError("owned watcher exited before readiness")
        if (observed["parent_pid"] != row["process"].pid
                or observed["identity"][2:] != (row["process"].pid, row["process"].pid)):
            raise RuntimeError("owned watcher parent, group or session differs")
        start_identity = (observed["identity"][0], *observed["identity"][2:])
        if row.get("watcher_start_identity") is None:
            row["watcher_start_identity"] = start_identity
        elif row["watcher_start_identity"] != start_identity:
            raise RuntimeError("owned watcher startup identity changed")
        if tuple(directory_identity(path) for path in (workspace, workspace / ".runner")) != directory_ids:
            raise RuntimeError("private watcher readiness directory identity changed")
        if observed["identity"][1] != expected_command:
            sample["reason"] = "awaiting_exact_report_exec"
            return False
        snapshot = workspace / "section-header_info.json"
        if not snapshot.exists():
            sample["reason"] = "awaiting_this_run_snapshot"
            return False
        info = snapshot.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_LOG:
            raise RuntimeError("fresh watcher snapshot is not a bounded ordinary file")
        value = json.loads(snapshot.read_bytes())
        if (not isinstance(value, dict) or value.get("name") != "header_info" or value.get("text") != "TEST_ONLY header snapshot"
                or type(value.get("revision")) is not int or value["revision"] != 1
                or value.get("complete") is not True):
            raise RuntimeError("fresh watcher startup snapshot differs from this run")
        sample["snapshot"] = value
        sample["reason"] = "exact_report_exec_parent_and_fresh_snapshot"
        row["watcher_identity"] = observed["identity"]
        return True
    except BaseException as error:
        sample["reason"] = str(error)
        raise


def pid_live(pid):
    return pid_identity(pid) is not None


def watcher_live(row):
    expected = row.get("watcher_identity")
    return expected is not None and pid_identity(row["watcher_pid"]) == expected


def signal_owned_group(row, number):
    # Each row binds the private PID/group at start_new_session=True spawn.
    # Its direct leader stays unreaped through the last group signal.
    process = row["process"]
    expected = (process.pid, process.pid)
    if process.reaped is not False or row.get("spawn_group_identity") != expected:
        raise RuntimeError("owned group signal requires its unreaped spawn identity")
    # poll observes without reaping. Even an exited leader reserves this group
    # until cleanup has signaled and observed every remaining live member.
    status = process.poll()
    if status is None:
        try:
            current = (os.getpgid(process.pid), os.getsid(process.pid))
        except ProcessLookupError:
            # Exit can happen after the first live observation. Only a second
            # nonreaping exit observation permits the retained spawn identity.
            status = process.poll()
            if type(status) is not int or process.reaped is not False:
                raise
            current = None
        if current is not None and current != expected:
            raise RuntimeError("owned direct child's process group changed")
    elif type(status) is not int:
        raise RuntimeError("owned leader has no known nonreaping exit observation")
    else:
        # Darwin no longer exposes getpgid/getsid for an exited leader. The
        # waitid/WNOWAIT observation retains its PID and the private spawn group.
        current = None
    row.setdefault("signal_observations", []).append({"signal": number,
        "nonreaping_exit_status": status, "spawn_group_identity": expected,
        "live_leader_group_identity": current, "identity_reservation_retained": True})
    if not group_has_live_members(process.pid):
        return
    try:
        os.killpg(process.pid, number)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin may retain an inaccessible group containing only zombies.
        if group_has_live_members(process.pid):
            raise


def owner_main(workspace, evidence, ignored_signals):
    """Be the actual direct parent, retaining watcher output even after SIGKILL."""
    if ignored_signals:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    watcher = None
    with (evidence / "watcher.stdout").open("xb") as stdout, \
            (evidence / "watcher.stderr").open("xb") as stderr:
        os.chmod(evidence / "watcher.stdout", 0o600)
        os.chmod(evidence / "watcher.stderr", 0o600)
        try:
            watcher = subprocess.Popen([INTERPRETER, "-B", str(REPORT), "watch-sections",
                str(workspace), str(os.getpid())], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            private_json(evidence / "owner-ready.json", {"owner_pid": os.getpid(), "watcher_pid": watcher.pid})
            deadline = time.monotonic() + 60
            recorded_exit = False
            while time.monotonic() < deadline:
                code = watcher.poll()
                if code is not None and not recorded_exit:
                    private_json(evidence / "watcher-exit.json", {"returncode": watcher.wait(timeout=2)})
                    recorded_exit = True
                readable, _, _ = select.select([sys.stdin], [], [], 0.05)
                if readable and not os.read(sys.stdin.fileno(), 1):
                    return
            raise RuntimeError("owned test parent exceeded its deadline")
        finally:
            if watcher is not None:
                if watcher.poll() is None:
                    watcher.terminate()
                    try:
                        watcher.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        watcher.kill()
                watcher.wait(timeout=2)


@unittest.skipUnless(sys.platform in ("linux", "darwin") and hasattr(os, "waitid") and hasattr(os, "WNOWAIT"),
                     "watcher ownership requires Linux/Darwin nonreaping observation, signals and flock")
class WatcherLifecycle(unittest.TestCase):
    def setUp(self):
        parent = os.environ.get("SINAN_WATCHER_TEST_EVIDENCE")
        if parent is not None:
            candidate = Path(parent)
            if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_dir():
                raise ValueError("evidence parent must be an existing absolute ordinary directory")
            parent = str(candidate.resolve())
        self.evidence = Path(tempfile.mkdtemp(prefix="sinan-watcher-test-", dir=parent)).resolve()
        self.evidence.chmod(0o700)
        self.groups = []
        self.handles = []
        self.logs = []
        self.addCleanup(self.cleanup)
        # This process is deliberately outside all owner/watcher groups.
        self.sentinel = ObservedProcess([INTERPRETER, "-B", "-c", "import time;time.sleep(60)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        self.groups.append({"process": self.sentinel, "watcher_pid": None, "watcher_identity": None,
                            "spawn_group_identity": (self.sentinel.pid, self.sentinel.pid)})
        private_json(self.evidence / "test-identity.json", {"test": self.id(), "sentinel_pid": self.sentinel.pid})

    def diagnostics(self):
        rows = []
        for path in self.logs:
            if path.exists():
                with path.open("rb") as stream:
                    rows.append(path.name + ": " + stream.read(8192).decode("utf-8", errors="replace"))
        return "Evidence retained at " + str(self.evidence) + "\n" + "\n".join(rows)

    def bounded_logs(self):
        for path in self.logs:
            self.assertLessEqual(path.stat().st_size, MAX_LOG, self.diagnostics())

    def wait_for(self, predicate, description, seconds=WAIT_SECONDS):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.bounded_logs()
            if predicate():
                return
            time.sleep(0.03)
        self.fail(description + "\n" + self.diagnostics())

    def assert_sentinel(self):
        self.assertIsNone(self.sentinel.poll(), self.diagnostics())

    def cleanup(self):
        failures = []
        observations = []
        for row in reversed(self.groups):
            process, watcher_pid = row["process"], row["watcher_pid"]
            observed = {"owner_pid": process.pid, "watcher_pid": watcher_pid,
                        "readiness_bound": row.get("watcher_identity") is not None,
                        "watcher_start_identity": row.get("watcher_start_identity"),
                        "spawn_group_identity": row.get("spawn_group_identity")}
            observations.append(observed)
            try:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                signal_owned_group(row, signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                signal_owned_group(row, signal.SIGKILL)
                process.wait(timeout=2)
                deadline = time.monotonic() + 3
                while group_has_live_members(process.pid) and time.monotonic() < deadline:
                    time.sleep(0.03)
                observed["zero_live_owned_group"] = not group_has_live_members(process.pid)
                observed["watcher_after_signals"] = None if watcher_pid is None else pid_observation(watcher_pid)
                if not observed["zero_live_owned_group"] or observed["watcher_after_signals"] is not None:
                    raise RuntimeError("actual owned watcher/group cleanup was not confirmed")
            except BaseException as error:
                failures.append(type(error).__name__)
                observed["failure"] = type(error).__name__
            finally:
                if (observed.get("zero_live_owned_group") and "watcher_after_signals" in observed
                        and observed["watcher_after_signals"] is None):
                    try:
                        # Release the leader only after actual group/PID exit
                        # confirmation; a cleanup failure retains its identity.
                        process.reap(timeout=2)
                    except BaseException as error:
                        failures.append(type(error).__name__)
                        observed["reap_failure"] = type(error).__name__
                observed["identity_reservation_retained"] = not process.reaped
                observed["signal_observations"] = row.get("signal_observations", [])
        for handle in self.handles:
            handle.close()
        private_json(self.evidence / "cleanup.json", {"failures": failures, "materials_retained": True,
            "direct_children_reaped": all(row["process"].reaped for row in self.groups),
            "actual_cleanup_observations": observations})
        if failures:
            raise AssertionError("Owned process cleanup failed: " + ",".join(failures) + "\n" + self.diagnostics())

    def workspace(self, name):
        workspace = self.evidence / name
        workspace.mkdir(mode=0o700)
        (workspace / ".runner").mkdir(mode=0o700)
        results = workspace / ".nodequality-owned" / "BenchOs" / "result"
        results.mkdir(parents=True)
        for name, content in {
                "header_info.log": "TEST_ONLY header snapshot",
                "hardware_quality.log": "TEST_ONLY incomplete newer hardware",
                "hardware_quality.json": "{",
                "ip_quality.log": "TEST_ONLY completed IP snapshot",
                "ip_quality.json": '{"owned":true}',
                "net_quality.log": "TEST_ONLY partial network snapshot",
                "net_quality.json": '{"owned":true}'}.items():
            (results / name).write_text(content)
        historical = {"name": "hardware_quality", "text": "TEST_ONLY completed historical hardware",
                      "complete": True, "revision": 9, "collected_at": 1}
        private_json(workspace / "section-hardware_quality.json", historical)
        return workspace, results

    def start_owner(self, workspace, ignored_signals=False):
        snapshot = workspace / "section-header_info.json"
        self.assertFalse(snapshot.exists() or snapshot.is_symlink(), self.diagnostics())
        directory_ids = tuple(directory_identity(path) for path in (workspace, workspace / ".runner"))
        directory = self.evidence / ("owner-" + str(len(self.groups)))
        directory.mkdir(mode=0o700)
        stdout, stderr = directory / "owner.stdout", directory / "owner.stderr"
        for path in (stdout, stderr):
            handle = path.open("xb")
            os.chmod(path, 0o600)
            self.handles.append(handle)
        self.logs.extend((stdout, stderr))
        process = ObservedProcess([INTERPRETER, "-B", str(Path(__file__).resolve()), "--owner",
            str(workspace), str(directory), "ignore" if ignored_signals else "normal"],
            stdin=subprocess.PIPE, stdout=self.handles[-2], stderr=self.handles[-1], start_new_session=True)
        row = {"process": process, "watcher_pid": None, "watcher_identity": None, "directory": directory,
               "readiness_samples": [], "readiness_started": time.monotonic(),
               "spawn_group_identity": (process.pid, process.pid)}
        self.groups.append(row)
        ready = directory / "owner-ready.json"
        self.wait_for(lambda: ready.exists(), "actual direct owner did not start")
        identity = json.loads(ready.read_bytes())
        self.assertEqual(identity["owner_pid"], process.pid)
        row["watcher_pid"] = identity["watcher_pid"]
        self.logs.extend((directory / "watcher.stdout", directory / "watcher.stderr"))
        expected = " ".join((INTERPRETER, "-B", str(REPORT), "watch-sections", str(workspace), str(process.pid)))
        try:
            self.wait_for(lambda: readiness_probe(row, expected, workspace, directory_ids),
                          "watcher did not complete exact exec and fresh snapshot readiness")
        finally:
            private_json(directory / "readiness-observations.json", {"expected_command": expected,
                "owner_pid": process.pid, "watcher_pid": row["watcher_pid"],
                "directory_identities": directory_ids, "samples": row["readiness_samples"],
                "bound_identity": row["watcher_identity"], "startup_identity": row.get("watcher_start_identity"),
                "trusted_interpreter_image": INTERPRETER})
        self.assertIsNone(process.poll(), self.diagnostics())
        self.assertTrue(watcher_live(row), self.diagnostics())
        self.assert_sentinel()
        return row

    def assert_watcher_exits(self, row):
        self.wait_for(lambda: not watcher_live(row), "owned watcher did not exit")
        self.assert_sentinel()

    def test_sigkill_owner_exits_watcher_with_workspace_retained_or_removed(self):
        for remove_workspace in (False, True):
            with self.subTest(remove_workspace=remove_workspace):
                workspace, _ = self.workspace("kill-" + str(remove_workspace))
                historical = (workspace / "section-hardware_quality.json").read_bytes()
                row = self.start_owner(workspace)
                row["process"].kill()
                self.assertEqual(row["process"].wait(timeout=2), -signal.SIGKILL)
                if remove_workspace:
                    shutil.rmtree(workspace)
                self.assert_watcher_exits(row)
                if not remove_workspace:
                    self.assertEqual((workspace / "section-hardware_quality.json").read_bytes(), historical)

    def test_noncanonical_or_nonparent_owner_is_rejected_without_publication(self):
        workspace, _ = self.workspace("mismatch")
        historical = (workspace / "section-hardware_quality.json").read_bytes()
        for index, value in enumerate((str(self.sentinel.pid), "1", "0", "-1", "02", "+" + str(os.getpid()), "bad")):
            with self.subTest(owner=value):
                stdout, stderr = self.evidence / ("mismatch-" + str(index) + ".stdout"), self.evidence / ("mismatch-" + str(index) + ".stderr")
                handles = [path.open("xb") for path in (stdout, stderr)]
                for path in (stdout, stderr):
                    os.chmod(path, 0o600)
                self.handles.extend(handles)
                self.logs.extend((stdout, stderr))
                process = ObservedProcess([INTERPRETER, "-B", str(REPORT), "watch-sections", str(workspace), value],
                    stdin=subprocess.DEVNULL, stdout=handles[0], stderr=handles[1], start_new_session=True)
                self.groups.append({"process": process, "watcher_pid": None, "watcher_identity": None,
                                    "spawn_group_identity": (process.pid, process.pid)})
                self.wait_for(lambda: process.poll() is not None, "invalid owner was accepted")
                self.assertNotEqual(process.wait(timeout=2), 0, self.diagnostics())
                self.assertFalse((workspace / "section-header_info.json").exists())
                self.assertEqual((workspace / "section-hardware_quality.json").read_bytes(), historical)
                self.assert_sentinel()

    def test_inherited_ignored_term_and_hup_are_restored_in_watcher(self):
        for number in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=number):
                workspace, _ = self.workspace("signal-" + str(number))
                row = self.start_owner(workspace, ignored_signals=True)
                os.kill(row["watcher_pid"], number)
                self.assert_watcher_exits(row)
                exit_record = row["directory"] / "watcher-exit.json"
                self.wait_for(lambda: exit_record.exists(), "actual parent did not reap stopped watcher")
                self.assertIsInstance(json.loads(exit_record.read_bytes())["returncode"], int)
                self.assertIsNone(row["process"].poll(), self.diagnostics())

    def test_busy_chapter_lock_cannot_keep_an_orphan_alive(self):
        workspace, results = self.workspace("busy-lock")
        row = self.start_owner(workspace)
        previous = (workspace / "section-header_info.json").read_bytes()
        with (workspace / ".sections.lock").open("r+") as lock:
            def acquire_fixture_lock():
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return True
                except BlockingIOError:
                    return False
            self.wait_for(acquire_fixture_lock, "test fixture could not acquire its independent chapter lock")
            (results / "header_info.log").write_text("TEST_ONLY newer header while lock busy")
            # Give a live iteration a chance to encounter the independently held
            # lock; keep it held throughout the parent-death exit deadline.
            end = time.monotonic() + 1.3
            while time.monotonic() < end:
                self.bounded_logs()
                self.assertTrue(watcher_live(row), self.diagnostics())
                time.sleep(0.03)
            row["process"].kill()
            row["process"].wait(timeout=2)
            self.assert_watcher_exits(row)
            self.assertEqual((workspace / "section-header_info.json").read_bytes(), previous)

    def test_fifo_source_cannot_keep_an_orphan_alive_or_replace_saved_chapters(self):
        for filename in ("header_info.log", "upload.base64"):
            with self.subTest(filename=filename):
                workspace, results = self.workspace("fifo-" + filename.replace(".", "-"))
                row = self.start_owner(workspace)
                previous = (workspace / "section-header_info.json").read_bytes()
                path = workspace / filename if filename == "upload.base64" else results / filename
                path.unlink(missing_ok=True)
                os.mkfifo(path, 0o600)
                # No writer opens this FIFO. A path-based blocking open would
                # remain stuck after the direct owner is killed.
                end = time.monotonic() + 1.3
                while time.monotonic() < end:
                    self.bounded_logs()
                    self.assertTrue(watcher_live(row), self.diagnostics())
                    time.sleep(0.03)
                row["process"].kill()
                row["process"].wait(timeout=2)
                self.assert_watcher_exits(row)
                self.assertEqual((workspace / "section-header_info.json").read_bytes(), previous)

    def test_runtime_disappearance_or_inode_replacement_exits_with_owner_alive(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                workspace, _ = self.workspace("runtime-" + str(replacement))
                row = self.start_owner(workspace)
                historical = (workspace / "section-hardware_quality.json").read_bytes()
                (workspace / ".runner").rename(workspace / ".runner-retained")
                if replacement:
                    (workspace / ".runner").mkdir(mode=0o700)
                self.assert_watcher_exits(row)
                self.assertIsNone(row["process"].poll(), self.diagnostics())
                self.assertEqual((workspace / "section-hardware_quality.json").read_bytes(), historical)

    def test_workspace_inode_replacement_is_not_followed(self):
        workspace, _ = self.workspace("workspace-original")
        row = self.start_owner(workspace)
        historical = (workspace / "section-hardware_quality.json").read_bytes()
        displaced = self.evidence / "workspace-retained"
        workspace.rename(displaced)
        workspace.mkdir(mode=0o700)
        (workspace / ".runner").mkdir(mode=0o700)
        self.assert_watcher_exits(row)
        self.assertIsNone(row["process"].poll(), self.diagnostics())
        self.assertEqual((displaced / "section-hardware_quality.json").read_bytes(), historical)
        self.assertEqual(set(path.name for path in workspace.iterdir()), {".runner"})

    def test_real_snapshots_keep_completed_history_and_do_not_invent_completeness(self):
        workspace, results = self.workspace("snapshots")
        historical = (workspace / "section-hardware_quality.json").read_bytes()
        row = self.start_owner(workspace)
        ip = workspace / "section-ip_quality.json"
        network = workspace / "section-net_quality.json"
        self.wait_for(lambda: ip.exists() and network.exists(), "available chapters did not publish")
        self.assertTrue(json.loads(ip.read_bytes())["complete"])
        self.assertFalse(json.loads(network.read_bytes())["complete"])
        first = json.loads(network.read_bytes())
        self.assertEqual(first["text"], "TEST_ONLY partial network snapshot")
        (results / "net_quality.log").write_text("TEST_ONLY later network snapshot")
        self.wait_for(lambda: json.loads(network.read_bytes())["text"] == "TEST_ONLY later network snapshot",
                      "live watcher did not collect the next snapshot")
        later = json.loads(network.read_bytes())
        self.assertGreater(later["revision"], first["revision"])
        self.assertFalse(later["complete"])
        self.assertEqual((workspace / "section-hardware_quality.json").read_bytes(), historical)
        row["process"].kill()
        row["process"].wait(timeout=2)
        self.assert_watcher_exits(row)
        self.assertEqual((workspace / "section-hardware_quality.json").read_bytes(), historical)


class PublicationDirectoryContracts(unittest.TestCase):
    def test_replacement_before_source_open_read_or_atomic_rename_cannot_receive_old_publication(self):
        for stage, invocation in (("directory_open", "watcher"), ("source_open", "watcher"),
                                  ("source_read", "watcher"), ("atomic_rename", "watcher"),
                                  ("directory_open", "snapshot"), ("source_open", "snapshot"),
                                  ("source_read", "snapshot"), ("atomic_rename", "snapshot")):
            with self.subTest(stage=stage, invocation=invocation), tempfile.TemporaryDirectory(prefix="sinan-watcher-publication-") as name:
                root = Path(name)
                workspace = root / "workspace"
                workspace.mkdir(mode=0o700)
                (workspace / ".runner").mkdir(mode=0o700)
                result = workspace / ".nodequality-owned" / "BenchOs" / "result"
                result.mkdir(parents=True)
                (result / "header_info.log").write_text("TEST_ONLY original source read before replacement")
                previous = {"name": "header_info", "text": "TEST_ONLY previous original preview",
                            "complete": False, "revision": 4, "collected_at": 1}
                private_json(workspace / "section-header_info.json", previous)
                original_identity = directory_identity(workspace)
                original_result_identity = directory_identity(result)
                displaced = root / "original-retained"
                reached, released = threading.Event(), threading.Event()
                errors, observations = [], []
                replacement = {"name": "header_info", "text": "TEST_ONLY new owner chapter",
                               "complete": False, "revision": 73, "collected_at": 2}
                replacement_bytes = json.dumps(replacement).encode()

                def replace_workspace():
                    try:
                        if not reached.wait(timeout=3):
                            raise RuntimeError("publisher did not reach the source/publication barrier")
                        workspace.rename(displaced)
                        workspace.mkdir(mode=0o700)
                        (workspace / ".runner").mkdir(mode=0o700)
                        (workspace / "section-header_info.json").write_bytes(replacement_bytes)
                        (workspace / ".sections.lock").write_bytes(b"TEST_ONLY replacement lock")
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        released.set()

                spec = importlib.util.spec_from_file_location("publication_report", REPORT)
                report = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(report)
                publish, replace, open_file = report.publish_sections, report.os.replace, report.os.open

                def pause(directory_fd):
                    metadata = os.fstat(directory_fd)
                    observations.append((metadata.st_dev, metadata.st_ino))
                    reached.set()
                    if not released.wait(timeout=3):
                        raise RuntimeError("replacement fixture did not release publication")

                def publish_after_barrier(*args, **kwargs):
                    pause(kwargs["publication_fd"])
                    return publish(*args, **kwargs)

                def rename_after_barrier(*args, **kwargs):
                    if args[1] == "section-header_info.json":
                        self.assertEqual(kwargs["src_dir_fd"], kwargs["dst_dir_fd"])
                        pause(kwargs["dst_dir_fd"])
                    return replace(*args, **kwargs)

                def open_after_barrier(name, flags, *args, **kwargs):
                    target = ".nodequality-owned" if stage == "directory_open" else "header_info.log"
                    if name == target and kwargs.get("dir_fd") is not None:
                        self.assertTrue(flags & os.O_NOFOLLOW)
                        if stage == "source_open":
                            self.assertTrue(flags & os.O_NONBLOCK)
                        pause(kwargs["dir_fd"])
                    return open_file(name, flags, *args, **kwargs)

                sleeps = []

                def bounded_next_iteration(_seconds):
                    sleeps.append(True)
                    if len(sleeps) > 1 or errors:
                        raise AssertionError("watcher followed replacement or fixture failed")

                mutation = threading.Thread(target=replace_workspace)
                mutation.start()
                try:
                    if stage in ("directory_open", "source_open"):
                        publication_patch = mock.patch.object(report.os, "open", side_effect=open_after_barrier)
                    elif stage == "source_read":
                        publication_patch = mock.patch.object(report, "publish_sections", side_effect=publish_after_barrier)
                    else:
                        publication_patch = mock.patch.object(report.os, "replace", side_effect=rename_after_barrier)
                    with mock.patch.object(report.time, "sleep", side_effect=bounded_next_iteration), \
                            publication_patch:
                        if invocation == "watcher":
                            report.watch_sections(workspace, os.getppid())
                        else:
                            report.snapshot(workspace, blocking=False)
                finally:
                    released.set()
                    mutation.join(timeout=4)
                self.assertFalse(mutation.is_alive())
                self.assertEqual(errors, [])
                expected_identity = original_result_identity if stage == "source_open" else original_identity
                self.assertEqual(observations, [expected_identity])
                self.assertEqual((workspace / "section-header_info.json").read_bytes(), replacement_bytes)
                self.assertEqual((workspace / ".sections.lock").read_bytes(), b"TEST_ONLY replacement lock")
                self.assertEqual(set(path.name for path in workspace.iterdir()),
                                 {".runner", ".sections.lock", "section-header_info.json"})
                old = json.loads((displaced / "section-header_info.json").read_bytes())
                aborted = invocation == "watcher" and stage != "atomic_rename"
                self.assertEqual(old["text"], previous["text"] if aborted else "TEST_ONLY original source read before replacement")
                self.assertEqual(old["revision"], 4 if aborted else 5)
                self.assertEqual(stat.S_IMODE((displaced / "section-header_info.json").stat().st_mode), 0o600)
                self.assertEqual(list(displaced.glob(".section-header_info.json.*")), [])


class SourceReadContracts(unittest.TestCase):
    def report(self):
        spec = importlib.util.spec_from_file_location("source_read_report", REPORT)
        report = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(report)
        return report

    def test_regular_to_fifo_swap_before_open_is_rejected_without_reading_or_late_publication(self):
        for filename, invocation in (("header_info.log", "snapshot"), ("upload.base64", "snapshot"),
                                     ("header_info.log", "watcher"), ("upload.base64", "watcher")):
            with self.subTest(filename=filename, invocation=invocation), \
                    tempfile.TemporaryDirectory(prefix="sinan-watcher-source-swap-") as temporary:
                workspace = Path(temporary) / "workspace"
                workspace.mkdir(mode=0o700)
                (workspace / ".runner").mkdir(mode=0o700)
                result = workspace / ".nodequality-owned" / "BenchOs" / "result"
                result.mkdir(parents=True)
                path = workspace / filename if filename == "upload.base64" else result / filename
                path.write_bytes(b"TEST_ONLY regular source before the FIFO swap")
                previous = {"name": "header_info", "text": "TEST_ONLY saved original chapter",
                            "complete": True, "revision": 7, "collected_at": 1}
                private_json(workspace / "section-header_info.json", previous)
                saved = (workspace / "section-header_info.json").read_bytes()
                report = self.report()
                open_file = report.os.open
                seen = []
                owner = os.getppid()
                parent = [owner]

                def swap_before_open(name, flags, *args, **kwargs):
                    if name == filename and kwargs.get("dir_fd") is not None and not seen:
                        seen.append(flags)
                        path.unlink()
                        os.mkfifo(path, 0o600)
                        self.assertTrue(flags & os.O_NOFOLLOW)
                        self.assertTrue(flags & os.O_NONBLOCK)
                    return open_file(name, flags, *args, **kwargs)

                def lose_owner(_seconds):
                    parent[0] = 1

                with mock.patch.object(report.os, "open", side_effect=swap_before_open), \
                        mock.patch.object(report.os, "getppid", side_effect=lambda: parent[0]), \
                        mock.patch.object(report.time, "sleep", side_effect=lose_owner):
                    if invocation == "watcher":
                        report.watch_sections(workspace, owner)
                    else:
                        report.snapshot(workspace, blocking=False)
                self.assertEqual(len(seen), 1)
                self.assertEqual((workspace / "section-header_info.json").read_bytes(), saved)
                self.assertEqual(list(workspace.glob(".section-header_info.json.*")), [])

    def test_read_source_rejects_links_size_writable_mode_and_nonregular_files(self):
        report = self.report()
        with tempfile.TemporaryDirectory(prefix="sinan-watcher-source-contract-") as temporary:
            workspace = Path(temporary)
            path = workspace / "source"
            descriptor = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                self.assertIsNone(report.read_source_at(descriptor, "missing", 16, lambda: None))
                path.write_bytes(b"TEST_ONLY")
                path.chmod(0o600)
                self.assertEqual(report.read_source_at(descriptor, "source", 16, lambda: None), b"TEST_ONLY")
                path.chmod(0o666)
                with self.assertRaisesRegex(ValueError, "bounded owned ordinary"):
                    report.read_source_at(descriptor, "source", 16, lambda: None)
                path.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "bounded owned ordinary"):
                    report.read_source_at(descriptor, "source", 1, lambda: None)
                path.unlink()
                path.symlink_to(workspace / "missing")
                with self.assertRaises(OSError):
                    report.read_source_at(descriptor, "source", 16, lambda: None)
                path.unlink()
                os.mkfifo(path, 0o600)
                with self.assertRaisesRegex(ValueError, "bounded owned ordinary"):
                    report.read_source_at(descriptor, "source", 16, lambda: None)
                with self.assertRaisesRegex(ValueError, "name is invalid"):
                    report.read_source_at(descriptor, "../source", 16, lambda: None)
            finally:
                os.close(descriptor)

    def test_non_directory_components_never_harvest_logs_from_their_ancestors(self):
        for component in (".nodequality-owned", "BenchOs", "result"):
            with self.subTest(component=component), tempfile.TemporaryDirectory(prefix="sinan-watcher-nondirectory-") as temporary:
                workspace = Path(temporary)
                parent = workspace
                for name in (".nodequality-owned", "BenchOs", "result"):
                    if name == component:
                        (parent / name).write_text("TEST_ONLY ordinary file instead of directory")
                        (parent / "header_info.log").write_text("TEST_ONLY unrelated ancestor log")
                        break
                    parent = parent / name
                    parent.mkdir(mode=0o700)
                self.report().snapshot(workspace, blocking=False)
                self.assertFalse((workspace / "section-header_info.json").exists())
                self.assertFalse((workspace / ".sections.lock").exists())

    def test_nested_result_directory_replacement_before_open_rejects_new_inode(self):
        for component in (".nodequality-owned", "BenchOs", "result"):
            with self.subTest(component=component), tempfile.TemporaryDirectory(prefix="sinan-watcher-nested-swap-") as temporary:
                workspace = Path(temporary)
                result = workspace / ".nodequality-owned" / "BenchOs" / "result"
                result.mkdir(parents=True)
                (result / "header_info.log").write_text("TEST_ONLY original nested source")
                report = self.report()
                open_file = report.os.open
                selected = next(path for path in (result, result.parent, result.parent.parent) if path.name == component)
                changed = []

                def replace_before_open(name, flags, *args, **kwargs):
                    if name == component and kwargs.get("dir_fd") is not None and not changed:
                        changed.append(True)
                        selected.rename(selected.with_name(component + "-retained"))
                        selected.mkdir(mode=0o700)
                        replacement = selected
                        remaining = {".nodequality-owned": ("BenchOs", "result"), "BenchOs": ("result",), "result": ()}[component]
                        for child in remaining:
                            replacement = replacement / child
                            replacement.mkdir(mode=0o700)
                        (replacement / "header_info.log").write_text("TEST_ONLY replacement source must not publish")
                    return open_file(name, flags, *args, **kwargs)

                with mock.patch.object(report.os, "open", side_effect=replace_before_open):
                    with self.assertRaisesRegex(ValueError, "identity changed during open"):
                        report.snapshot(workspace, blocking=False)
                self.assertEqual(changed, [True])
                self.assertFalse((workspace / "section-header_info.json").exists())
                self.assertFalse((workspace / ".sections.lock").exists())

    def test_each_read_chunk_checks_owner_and_deadline_before_more_bytes(self):
        report = self.report()
        with tempfile.TemporaryDirectory(prefix="sinan-watcher-chunk-cancel-") as temporary:
            workspace = Path(temporary)
            (workspace / "source").write_bytes(b"x" * (128 * 1024))
            descriptor = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            checks = []

            def cancel_second_chunk():
                checks.append(True)
                if len(checks) == 3:
                    raise ValueError("TEST_ONLY owner changed before second bounded chunk")

            try:
                with self.assertRaisesRegex(ValueError, "before second bounded chunk"):
                    report.read_source_at(descriptor, "source", 128 * 1024, cancel_second_chunk)
                self.assertEqual(len(checks), 3)
            finally:
                os.close(descriptor)

    def test_cancellation_and_deadline_during_source_reads_drop_unpublished_bytes_and_close_fds(self):
        for interruption in ("owner_loss", "deadline"):
            with self.subTest(interruption=interruption), \
                    tempfile.TemporaryDirectory(prefix="sinan-watcher-read-cancel-") as temporary:
                workspace = Path(temporary)
                result = workspace / ".nodequality-owned" / "BenchOs" / "result"
                result.mkdir(parents=True)
                (result / "header_info.log").write_bytes(b"x" * (64 * 1024))
                (result / "hardware_quality.json").write_bytes(b"x" * (128 * 1024))
                previous = {"name": "header_info", "text": "TEST_ONLY previously saved chapter",
                            "complete": True, "revision": 8, "collected_at": 1}
                private_json(workspace / "section-header_info.json", previous)
                saved = (workspace / "section-header_info.json").read_bytes()
                report = self.report()
                source_read, open_file = report.read_source_at, report.os.open
                cancelled = [False]
                clock = [0.0]
                descriptors = []

                def record_open(*args, **kwargs):
                    descriptor = open_file(*args, **kwargs)
                    descriptors.append(descriptor)
                    return descriptor

                def interrupt_after_read(*args, **kwargs):
                    content = source_read(*args, **kwargs)
                    if args[1] == "header_info.log":
                        if interruption == "owner_loss":
                            cancelled[0] = True
                        else:
                            clock[0] = report.SNAPSHOT_SECONDS + 1
                    return content

                with mock.patch.object(report.os, "open", side_effect=record_open), \
                        mock.patch.object(report, "read_source_at", side_effect=interrupt_after_read), \
                        mock.patch.object(report.time, "monotonic", side_effect=lambda: clock[0]):
                    with self.assertRaisesRegex(ValueError, "stopped or exceeded its deadline"):
                        report.snapshot(workspace, blocking=False,
                                        cancelled=(lambda: cancelled[0]) if interruption == "owner_loss" else None)
                self.assertEqual((workspace / "section-header_info.json").read_bytes(), saved)
                self.assertFalse((workspace / ".sections.lock").exists())
                self.assertTrue(descriptors)
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)


class CollectorDirectoryContracts(unittest.TestCase):
    def report(self):
        spec = importlib.util.spec_from_file_location("collector_directory_report", REPORT)
        report = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(report)
        return report

    def archive(self, report):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, _ in report.SECTIONS:
                archive.writestr(name + ".log", "TEST_ONLY complete " + name)
                if name != "header_info":
                    archive.writestr(name + ".json", '{"TEST_ONLY": true}')
        return base64.b64encode(output.getvalue())

    def test_capture_response_stream_and_render_keep_original_directory_after_input_read(self):
        for operation in ("capture", "response", "stream", "render"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(prefix="sinan-collector-directory-") as temporary:
                workspace = Path(temporary) / "workspace"
                workspace.mkdir(mode=0o700)
                displaced = workspace.with_name("original-retained")
                report = self.report()
                encoded = self.archive(report)
                (workspace / "upload.base64").write_bytes(encoded)
                replacement_bytes = b"TEST_ONLY unrelated new owner"
                changed = []

                def replace_workspace():
                    if changed:
                        return
                    changed.append(True)
                    workspace.rename(displaced)
                    workspace.mkdir(mode=0o700)
                    for name in ("upload.base64", "result.txt", "report.zip", "upload-response.txt", "upload-status.txt", "log.txt"):
                        (workspace / name).write_bytes(replacement_bytes)

                class Input(io.BytesIO):
                    def read(self, *args):
                        value = super().read(*args)
                        replace_workspace()
                        return value

                    def read1(self, *args):
                        value = super().read1(*args)
                        replace_workspace()
                        return value

                source = encoded if operation == "capture" else b"TEST_ONLY streamed bytes\nSINAN_RESPONSE_STATUS:200"
                stdin = mock.Mock(buffer=Input(source))
                stdout = mock.Mock(buffer=io.BytesIO())
                archive_files = report.archive_files

                def replace_after_archive(*args, **kwargs):
                    value = archive_files(*args, **kwargs)
                    replace_workspace()
                    return value

                with mock.patch.object(report.sys, "stdin", stdin), mock.patch.object(report.sys, "stdout", stdout):
                    if operation == "capture":
                        report.capture(workspace)
                        self.assertEqual((displaced / "upload.base64").read_bytes(), encoded)
                        self.assertTrue((displaced / "section-header_info.json").exists())
                    elif operation == "response":
                        report.capture_response(workspace)
                        self.assertEqual((displaced / "upload-status.txt").read_bytes(), b"200")
                    elif operation == "stream":
                        report.stream_log(workspace / "log.txt")
                        self.assertEqual((displaced / "log.txt").read_bytes(), source)
                    else:
                        with mock.patch.object(report, "archive_files", side_effect=replace_after_archive):
                            report.render(workspace)
                        self.assertTrue((displaced / "result.txt").exists())
                        self.assertFalse((displaced / "upload.base64").exists())
                self.assertEqual(changed, [True])
                self.assertEqual(set(path.name for path in workspace.iterdir()),
                                 {"upload.base64", "result.txt", "report.zip", "upload-response.txt", "upload-status.txt", "log.txt"})
                for path in workspace.iterdir():
                    self.assertEqual(path.read_bytes(), replacement_bytes)

    def test_serialized_chapter_lock_wait_is_bounded_and_keeps_saved_bytes(self):
        with tempfile.TemporaryDirectory(prefix="sinan-collector-lock-deadline-") as temporary:
            workspace = Path(temporary)
            report = self.report()
            saved = {"name": "header_info", "text": "TEST_ONLY complete saved chapter",
                     "complete": True, "revision": 9, "collected_at": 1}
            private_json(workspace / "section-header_info.json", saved)
            previous = (workspace / "section-header_info.json").read_bytes()
            clock = [0.0]

            def advance(_seconds):
                clock[0] = report.SNAPSHOT_SECONDS + 1

            with mock.patch.object(report.fcntl, "flock", side_effect=BlockingIOError("TEST_ONLY busy")), \
                    mock.patch.object(report.time, "monotonic", side_effect=lambda: clock[0]), \
                    mock.patch.object(report.time, "sleep", side_effect=advance):
                with self.assertRaises(BlockingIOError):
                    report.save_section(workspace, "header_info", "TEST_ONLY pending replacement", True)
            self.assertEqual((workspace / "section-header_info.json").read_bytes(), previous)
            self.assertEqual(list(workspace.glob(".section-header_info.json.*")), [])


class ReadinessContracts(unittest.TestCase):
    def test_framework_interpreter_image_comes_only_from_trusted_local_metadata(self):
        with tempfile.TemporaryDirectory(prefix='sinan-watcher-interpreter-contract-') as name:
            version = Path(name).resolve() / 'Python.framework' / 'Versions' / '3.14'
            launcher = version / 'bin' / 'python3.14'
            image = version / 'Resources' / 'Python.app' / 'Contents' / 'MacOS' / 'Python'
            for path in (launcher, image):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('TEST_ONLY inert executable identity')
                path.chmod(0o700)
            metadata = {'PYTHONFRAMEWORK': 'Python', 'PYTHONFRAMEWORKINSTALLNAMEPREFIX': str(version)}
            with mock.patch.object(sys, 'platform', 'darwin'), \
                    mock.patch.object(sysconfig, 'get_config_var', side_effect=metadata.get):
                for executable in (launcher, image):
                    with self.subTest(executable=executable.name), mock.patch.object(sys, 'executable', str(executable)):
                        self.assertEqual(interpreter_image(), str(image))
                foreign = Path(name) / 'foreign-python'
                foreign.write_text('TEST_ONLY unrelated interpreter')
                foreign.chmod(0o700)
                with mock.patch.object(sys, 'executable', str(foreign)), self.assertRaisesRegex(RuntimeError, 'outside'):
                    interpreter_image()
                image.chmod(0o600)
                with mock.patch.object(sys, 'executable', str(launcher)), self.assertRaisesRegex(RuntimeError, 'executable'):
                    interpreter_image()

    def fixture(self, root):
        workspace, evidence = root / 'workspace', root / 'evidence'
        workspace.mkdir()
        (workspace / '.runner').mkdir()
        evidence.mkdir()
        process = mock.Mock(pid=1234)
        process.poll.return_value = None
        row = {'process': process, 'watcher_pid': 1235, 'watcher_identity': None,
               'directory': evidence, 'readiness_samples': [], 'readiness_started': time.monotonic()}
        identities = tuple(directory_identity(path) for path in (workspace, workspace / '.runner'))
        command = ' '.join((INTERPRETER, '-B', str(REPORT), 'watch-sections', str(workspace), '1234'))
        observed = {'parent_pid': 1234, 'state': 'S', 'identity': ('TEST_ONLY start', command, 1234, 1234)}
        return workspace, row, identities, command, observed

    def snapshot(self, workspace, revision=1):
        private_json(workspace / 'section-header_info.json', {'name': 'header_info',
            'text': 'TEST_ONLY header snapshot', 'complete': True, 'revision': revision, 'collected_at': 1})

    def test_preexec_identity_is_not_bound_until_exact_exec_and_fresh_snapshot(self):
        with tempfile.TemporaryDirectory(prefix='sinan-watcher-ready-contract-') as name:
            workspace, row, ids, command, observed = self.fixture(Path(name))
            preexec = dict(observed, identity=('TEST_ONLY start', 'TEST_ONLY inherited owner argv', 1234, 1234))
            with mock.patch(__name__ + '.pid_observation', side_effect=(preexec, observed, observed)):
                self.assertFalse(readiness_probe(row, command, workspace, ids))
                self.assertIsNone(row['watcher_identity'])
                self.assertFalse(readiness_probe(row, command, workspace, ids))
                self.assertIsNone(row['watcher_identity'])
                self.snapshot(workspace)
                self.assertTrue(readiness_probe(row, command, workspace, ids))
            self.assertEqual(row['watcher_identity'], observed['identity'])
            self.assertEqual([sample['reason'] for sample in row['readiness_samples']],
                ['awaiting_exact_report_exec', 'awaiting_this_run_snapshot', 'exact_report_exec_parent_and_fresh_snapshot'])

    def test_foreign_interpreter_and_start_identity_drift_cannot_bind_readiness(self):
        for case in ('foreign_interpreter', 'changed_start'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix='sinan-watcher-image-refusal-') as name:
                workspace, row, ids, command, observed = self.fixture(Path(name))
                if case == 'foreign_interpreter':
                    foreign = 'TEST_ONLY_FOREIGN_INTERPRETER ' + command.split(' ', 1)[1]
                    observed = dict(observed, identity=('TEST_ONLY start', foreign, 1234, 1234))
                    self.snapshot(workspace)
                    with mock.patch(__name__ + '.pid_observation', return_value=observed):
                        self.assertFalse(readiness_probe(row, command, workspace, ids))
                    self.assertEqual(row['readiness_samples'][-1]['reason'], 'awaiting_exact_report_exec')
                else:
                    with mock.patch(__name__ + '.pid_observation', return_value=observed):
                        self.assertFalse(readiness_probe(row, command, workspace, ids))
                    self.snapshot(workspace)
                    changed = dict(observed, identity=('TEST_ONLY different start', command, 1234, 1234))
                    with mock.patch(__name__ + '.pid_observation', return_value=changed), \
                            self.assertRaisesRegex(RuntimeError, 'startup identity changed'):
                        readiness_probe(row, command, workspace, ids)
                self.assertIsNone(row['watcher_identity'])

    def test_unbound_watcher_cleanup_requires_actual_zero_live_observation(self):
        for live in (False, True):
            with self.subTest(live=live), tempfile.TemporaryDirectory(prefix='sinan-watcher-cleanup-contract-') as name:
                case = WatcherLifecycle('test_busy_chapter_lock_cannot_keep_an_orphan_alive')
                case.evidence, case.handles, case.logs = Path(name), [], []
                process = mock.Mock(pid=1234, stdin=None, reaped=False)
                process.reap.side_effect = lambda **kwargs: setattr(process, 'reaped', True)
                case.groups = [{'process': process, 'watcher_pid': 1235, 'watcher_identity': None,
                                'watcher_start_identity': ('TEST_ONLY start', 1234, 1234),
                                'spawn_group_identity': (1234, 1234)}]
                observation = {'parent_pid': 1, 'state': 'S',
                    'identity': ('TEST_ONLY start', 'TEST_ONLY report command', 1234, 1234)} if live else None
                with mock.patch(__name__ + '.signal_owned_group') as signal_group, \
                        mock.patch(__name__ + '.group_has_live_members', return_value=False), \
                        mock.patch(__name__ + '.pid_observation', return_value=observation) as observe:
                    if live:
                        with self.assertRaisesRegex(AssertionError, 'cleanup failed'):
                            case.cleanup()
                    else:
                        case.cleanup()
                observe.assert_called_once_with(1235)
                self.assertEqual([call.args[1] for call in signal_group.call_args_list], [signal.SIGTERM, signal.SIGKILL])
                receipt = json.loads((case.evidence / 'cleanup.json').read_bytes())
                self.assertEqual(receipt['direct_children_reaped'], not live)
                self.assertEqual(bool(receipt['failures']), live)
                actual = receipt['actual_cleanup_observations'][0]
                self.assertFalse(actual['readiness_bound'])
                expected = dict(observation, identity=list(observation['identity'])) if live else None
                self.assertEqual(actual['watcher_after_signals'], expected)
                self.assertEqual(actual['identity_reservation_retained'], live)

    def test_group_signals_require_known_unreaped_spawn_identity_and_exact_live_leader(self):
        for case in ('exited', 'live', 'exit_race', 'missing_live', 'reaped', 'live_drift',
                     'unknown_spawn', 'unknown_status', 'live_permission_error'):
            with self.subTest(case=case):
                process = mock.Mock(pid=1234, reaped=False)
                process.poll.return_value = 0 if case == 'exited' else None
                row = {'process': process, 'spawn_group_identity': (1234, 1234)}
                if case == 'reaped':
                    process.reaped = True
                elif case == 'unknown_spawn':
                    del row['spawn_group_identity']
                elif case == 'unknown_status':
                    process.poll.return_value = 'TEST_ONLY unknown status'
                elif case in ('exit_race', 'missing_live'):
                    process.poll.side_effect = (None, 0 if case == 'exit_race' else None)
                with mock.patch.object(os, 'getpgid', return_value=5678 if case == 'live_drift' else 1234) as pgid, \
                        mock.patch.object(os, 'getsid', return_value=1234) as sid, \
                        mock.patch(__name__ + '.group_has_live_members', return_value=True), \
                        mock.patch.object(os, 'killpg') as kill:
                    if case in ('exit_race', 'missing_live'):
                        pgid.side_effect = ProcessLookupError('TEST_ONLY leader metadata disappeared')
                    if case == 'live_permission_error':
                        kill.side_effect = PermissionError('TEST_ONLY live group permission error')
                        with self.assertRaises(PermissionError):
                            signal_owned_group(row, signal.SIGTERM)
                    elif case in ('exited', 'live', 'exit_race'):
                        signal_owned_group(row, signal.SIGTERM)
                        kill.assert_called_once_with(1234, signal.SIGTERM)
                    elif case == 'missing_live':
                        with self.assertRaises(ProcessLookupError):
                            signal_owned_group(row, signal.SIGTERM)
                        kill.assert_not_called()
                    else:
                        with self.assertRaises(RuntimeError):
                            signal_owned_group(row, signal.SIGTERM)
                        kill.assert_not_called()
                    if case in ('exited', 'reaped', 'unknown_spawn', 'unknown_status'):
                        pgid.assert_not_called()
                        sid.assert_not_called()
                    elif case in ('exit_race', 'missing_live'):
                        pgid.assert_called_once_with(1234)
                        sid.assert_not_called()
                self.assertEqual(process.reaped, case == 'reaped')

    def test_exited_child_foreign_parent_and_changed_private_runtime_never_become_ready(self):
        for case in ('owner_exit', 'watcher_exit', 'exit_receipt', 'foreign_parent', 'foreign_group', 'changed_runtime'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix='sinan-watcher-ready-refusal-') as name:
                workspace, row, ids, command, observed = self.fixture(Path(name))
                self.snapshot(workspace)
                if case == 'owner_exit':
                    row['process'].poll.return_value = 7
                elif case == 'watcher_exit':
                    observed = None
                elif case == 'exit_receipt':
                    private_json(row['directory'] / 'watcher-exit.json', {'returncode': 0})
                elif case == 'foreign_parent':
                    observed = dict(observed, parent_pid=5678)
                elif case == 'foreign_group':
                    observed = dict(observed, identity=('TEST_ONLY start', command, 5678, 5678))
                else:
                    (workspace / '.runner').rename(workspace / '.runner-retained')
                    (workspace / '.runner').mkdir()
                with mock.patch(__name__ + '.pid_observation', return_value=observed), self.assertRaises(RuntimeError):
                    readiness_probe(row, command, workspace, ids)
                self.assertIsNone(row['watcher_identity'])
                self.assertNotEqual(row['readiness_samples'][-1]['reason'], 'pending')

    def test_historical_snapshot_and_sample_overflow_are_refused(self):
        with tempfile.TemporaryDirectory(prefix='sinan-watcher-ready-bounds-') as name:
            workspace, row, ids, command, observed = self.fixture(Path(name))
            self.snapshot(workspace, revision=9)
            with mock.patch(__name__ + '.pid_observation', return_value=observed):
                with self.assertRaisesRegex(RuntimeError, 'snapshot differs'):
                    readiness_probe(row, command, workspace, ids)
            row['readiness_samples'] = [{}] * 64
            with mock.patch(__name__ + '.pid_observation') as observe, self.assertRaisesRegex(RuntimeError, 'sample limit'):
                readiness_probe(row, command, workspace, ids)
            observe.assert_not_called()
            self.assertIsNone(row['watcher_identity'])


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--owner":
        owner_main(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4] == "ignore")
    else:
        unittest.main()
