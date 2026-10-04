#!/usr/bin/env python3
"""Pure recovery/helper tests with TEST_ONLY host and command observations."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
RECOVERY = ROOT / "crates/agent-core/src/system_network/recovery.py"
FILES = ROOT / "crates/agent-core/src/system/managed_files.py"
spec = importlib.util.spec_from_file_location("test_only_recovery", RECOVERY)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
IDENTITY = "00000000-0000-0000-0000-000000000001"

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "network-recovery").mkdir()
        self.snapshot = self.root / "snapshot.json"
        self.marker = self.root / "network-recovery/current-sysctl.json"

    def prepare(self, snapshot, kind="sysctl", state="armed", identity=IDENTITY):
        self.marker = self.root / ("network-recovery/current-" + kind + ".json")
        self.marker.write_text(json.dumps({"id":identity,"kind":kind,"state":state}))
        self.snapshot.write_text(json.dumps(snapshot))

    def execute(self, command, kind="sysctl", run=None):
        # Production root ownership is replaced only in this local, isolated test wrapper.
        with mock.patch.object(recovery, "read_json", side_effect=lambda path:json.loads(Path(path).read_text())), mock.patch.object(recovery, "command", side_effect=command):
            if run:
                with mock.patch.object(recovery.subprocess, "run", side_effect=run):
                    return recovery.recover(str(self.root), kind, IDENTITY, str(self.snapshot))
            return recovery.recover(str(self.root), kind, IDENTITY, str(self.snapshot))

    def test_new_snapshot_binding_prevents_old_timer_actions(self):
        self.prepare({}, identity="00000000-0000-0000-0000-000000000002")
        calls = []
        self.assertEqual(self.execute(lambda args:calls.append(args)), "superseded")
        self.assertEqual(calls, [])

    def test_external_sysctl_value_is_retained_without_restore_write(self):
        self.prepare({"id":IDENTITY,"before":{"net.core.somaxconn":"128"},"desired":{"net.core.somaxconn":"256"}})
        calls = []
        def command(args):
            calls.append(args)
            self.assertEqual(args[1], "-n")
            return "512\n"
        self.assertEqual(self.execute(command), "refused")
        self.assertEqual(len(calls), 1)
        self.assertEqual(json.loads(self.marker.read_text())["state"], "refused")

    def test_sysctl_change_after_observation_is_rechecked_before_write(self):
        self.prepare({"id":IDENTITY,"before":{"net.core.somaxconn":"128"},"desired":{"net.core.somaxconn":"256"}})
        observations = iter(["256", "512"])
        self.assertEqual(self.execute(lambda args:next(observations) if args[1]=="-n" else self.fail("external value overwritten")), "refused")

    def test_partial_sysctl_apply_restores_only_applied_values_and_confirms(self):
        self.prepare({"id":IDENTITY,"before":{"net.core.somaxconn":"128","net.core.rmem_max":"1024"},"desired":{"net.core.somaxconn":"256","net.core.rmem_max":"2048"}})
        actual = {"net.core.somaxconn":"256", "net.core.rmem_max":"1024"}
        writes = []
        def command(args):
            if args[1] == "-n":
                return actual[args[2]]
            name,value = args[2].split("=",1)
            writes.append((name,value))
            actual[name] = value
            return ""
        self.assertEqual(self.execute(command), "restored")
        self.assertEqual(writes, [("net.core.somaxconn","128")])
        self.assertEqual(actual, {"net.core.somaxconn":"128","net.core.rmem_max":"1024"})
        self.assertTrue((self.root / "restored").exists())

    def test_external_firewall_change_is_retained_without_transaction(self):
        applied = "table inet sinan_0123456789ab { comment \"Managed by Sinan\"; }\n"
        external = applied.replace("; }", "; # TEST_ONLY external rule\n }")
        self.prepare({"table":"sinan_0123456789ab","previous":None,"observed_hash":hashlib.sha256(applied.encode()).hexdigest()}, kind="firewall")
        def command(args):
            return "table inet sinan_0123456789ab\n" if args[-1]=="tables" else external
        self.assertEqual(self.execute(command, "firewall", run=lambda *args,**kwargs:self.fail("external table overwritten")), "refused")

    def test_matching_firewall_uses_one_atomic_restore_batch(self):
        applied = "table inet sinan_0123456789ab { comment \"Managed by Sinan\"; }\n"
        previous = "table inet sinan_0123456789ab { comment \"Managed by Sinan\"; # TEST_ONLY prior\n }\n"
        self.prepare({"table":"sinan_0123456789ab","previous":previous,"observed_hash":hashlib.sha256(applied.encode()).hexdigest()}, kind="firewall")
        actual = [applied]
        transactions = []
        def command(args):
            return "table inet sinan_0123456789ab\n" if args[-1]=="tables" else actual[0]
        def run(args, **kwargs):
            descriptor = kwargs["pass_fds"][0]
            os.lseek(descriptor,0,os.SEEK_SET)
            transactions.append(os.read(descriptor,65536).decode())
            actual[0] = previous
            return types.SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
        self.assertEqual(self.execute(command,"firewall",run), "restored")
        self.assertEqual(transactions, ["delete table inet sinan_0123456789ab\n"+previous])

class FileHelperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.directory = self.root / "certificates"
        self.directory.mkdir(mode=0o700)
        self.path = self.directory / "tls.key"

    def call(self, request, path=None):
        path = path or self.path
        output = io.StringIO()
        actual_fstat = os.fstat
        def test_only_root_observation(descriptor):
            metadata = actual_fstat(descriptor)
            fields = {name:getattr(metadata,name) for name in dir(metadata) if name.startswith("st_")}
            fields["st_uid"] = fields["st_gid"] = 0
            if stat.S_ISDIR(fields["st_mode"]):
                fields["st_mode"] &= ~0o022
            return types.SimpleNamespace(**fields)
        with mock.patch.object(sys,"argv",[str(FILES),str(path)]), mock.patch.object(sys,"stdin",io.StringIO(json.dumps(request))), contextlib.redirect_stdout(output), mock.patch.object(os,"fstat",side_effect=test_only_root_observation), mock.patch.object(os,"fchown"):
            try:
                exec(compile(FILES.read_text(),str(FILES),"exec"),{"__name__":"__main__"})
            except SystemExit as error:
                self.assertEqual(error.code,0)
        return json.loads(output.getvalue())

    def snapshot(self):
        result = self.call({"action":"snapshot","maximum":65536,"root_owned":True})
        result.pop("content",None)
        return result

    def update(self, content, previous, metadata=None):
        import base64
        return self.call({"action":"update","maximum":65536,"root_owned":True,"content":base64.b64encode(content).decode() if content is not None else None,"expected":previous,"metadata":metadata or {"mode":0o600,"uid":0,"gid":0}})

    def test_private_new_file_and_exact_identity_replacement(self):
        previous = self.snapshot()
        applied = self.update(b"TEST_ONLY key v1", previous)
        self.assertEqual(self.path.read_bytes(),b"TEST_ONLY key v1")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)
        self.update(b"TEST_ONLY key v2",applied)
        self.assertEqual(self.path.read_bytes(),b"TEST_ONLY key v2")

    def test_late_external_file_changes_refuse_replace_or_cleanup(self):
        applied = self.update(b"TEST_ONLY key v1",self.snapshot())
        self.path.write_bytes(b"TEST_ONLY external")
        for payload in (None,b"TEST_ONLY key v2"):
            with self.assertRaises(ValueError):
                self.update(payload,applied)
            self.assertEqual(self.path.read_bytes(),b"TEST_ONLY external")

    def test_parent_replacement_cannot_write_new_directory(self):
        original = self.snapshot()
        old = self.root / "original"
        self.directory.rename(old)
        self.directory.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.update(b"TEST_ONLY key",original)
        self.assertFalse(self.path.exists())

    def test_symlink_and_hardlink_aliases_are_rejected(self):
        external = self.root / "external"
        external.write_bytes(b"TEST_ONLY external")
        self.path.symlink_to(external)
        with self.assertRaises(OSError):
            self.snapshot()
        self.path.unlink()
        os.link(external,self.path)
        with self.assertRaises(ValueError):
            self.snapshot()
        self.assertEqual(external.read_bytes(),b"TEST_ONLY external")

if __name__ == "__main__":
    unittest.main()
