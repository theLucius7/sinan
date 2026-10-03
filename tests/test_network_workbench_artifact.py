"""Offline inventory/archive tests with inert files and mocked tool identity calls."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'tools/network_workbench_artifact.py'
SPEC = importlib.util.spec_from_file_location('network_workbench_artifact', SCRIPT)
ARTIFACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACT)


class NetworkWorkbenchArtifactContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sinan-workbench-artifact-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'artifact.tar.gz'
        self.inventory = {
            'schema': 1, 'engine_version': '1.0.0',
            'interpreter': {'path': '/usr/bin/python3',
                            'sha256': hashlib.sha256(Path('/usr/bin/python3').read_bytes()).hexdigest()},
            'tools': {},
        }

    def invoke(self):
        inventory = self.root / 'inventory.json'
        inventory.write_text(json.dumps(self.inventory))
        with patch.object(sys, 'argv', [str(SCRIPT), '--inventory', str(inventory),
                                       '--output', str(self.output)]), contextlib.redirect_stdout(io.StringIO()) as stdout:
            ARTIFACT.main()
        return json.loads(stdout.getvalue())

    def inert_tool(self):
        program = self.root / 'iperf3'
        program.write_bytes(b'TEST ONLY: inert approved tool bytes, never executable')
        program.chmod(0o600)
        item = {'path': str(program), 'licensed': True, 'license': 'BSD-3-Clause',
                'source_url': 'https://example.com/authorized-tool-source',
                'sha256': hashlib.sha256(program.read_bytes()).hexdigest(), 'version': '3.16'}
        self.inventory['tools']['iperf3'] = item
        return program, item

    def test_engine_only_archive_retains_pins_and_never_claims_release_authorization(self):
        with patch.object(ARTIFACT.subprocess, 'run') as run:
            metadata = self.invoke()
        run.assert_not_called()
        self.assertFalse(metadata['signed'])
        self.assertFalse(metadata['release_authorized'])
        self.assertEqual(metadata['tool_count'], 0)
        self.assertEqual(metadata['sha256'], hashlib.sha256(self.output.read_bytes()).hexdigest())
        with tarfile.open(self.output, 'r:gz') as archive:
            self.assertEqual(set(archive.getnames()), {'sinan-network-workbench', 'tools-manifest.json', 'LICENSE'})
            self.assertEqual(archive.getmember('sinan-network-workbench').mode, 0o755)
            self.assertTrue(all(member.mtime == 0 for member in archive.getmembers()))
            manifest = json.loads(archive.extractfile('tools-manifest.json').read())
            self.assertEqual(manifest['interpreter'], self.inventory['interpreter'])
            self.assertEqual(archive.extractfile('sinan-network-workbench').read(),
                             (SCRIPT.parent / 'network-workbench.py').read_bytes())

    def test_invalid_schema_and_interpreter_digest_reject_before_tool_calls(self):
        for mutation, reason in [({'schema': 2}, 'versioned'),
                                 ({'interpreter': {'path': '/usr/bin/python3', 'sha256': '0' * 64}}, 'interpreter')]:
            with self.subTest(reason=reason), patch.object(ARTIFACT.subprocess, 'run') as run:
                original = dict(self.inventory)
                self.inventory.update(mutation)
                with self.assertRaisesRegex(ValueError, reason):
                    self.invoke()
                self.inventory = original
                self.assertFalse(self.output.exists())
                run.assert_not_called()

    def test_unlicensed_tool_rejects_without_version_execution(self):
        _, item = self.inert_tool()
        item['licensed'] = False
        with patch.object(ARTIFACT.subprocess, 'run') as run, self.assertRaisesRegex(ValueError, 'license'):
            self.invoke()
        run.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_digest_mismatch_rejects_without_version_execution(self):
        _, item = self.inert_tool()
        item['sha256'] = '0' * 64
        with patch.object(ARTIFACT.subprocess, 'run') as run, self.assertRaisesRegex(ValueError, 'digest'):
            self.invoke()
        run.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_approved_version_output_is_pinned_with_fixed_arguments(self):
        program, _ = self.inert_tool()
        result = subprocess.CompletedProcess([str(program), '--version'], 0, b'iperf 3.16\n', b'')
        with patch.object(ARTIFACT.subprocess, 'run', return_value=result) as run:
            metadata = self.invoke()
        run.assert_called_once_with([str(program), '--version'], capture_output=True, timeout=3, check=True)
        self.assertEqual(metadata['tool_count'], 1)
        with tarfile.open(self.output, 'r:gz') as archive:
            manifest = json.loads(archive.extractfile('tools-manifest.json').read())
        self.assertEqual(manifest['tools']['iperf3']['version_output_sha256'],
                         hashlib.sha256(result.stdout + result.stderr).hexdigest())

    def test_changed_tool_version_cannot_produce_archive(self):
        program, _ = self.inert_tool()
        result = subprocess.CompletedProcess([str(program), '--version'], 0, b'iperf 3.17\n', b'')
        with patch.object(ARTIFACT.subprocess, 'run', return_value=result), self.assertRaisesRegex(ValueError, 'identity'):
            self.invoke()
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
