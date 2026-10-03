#!/usr/bin/env python3
"""Exercise the current host upload boundary with inert tools and local reports."""
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'plugins/nodequality'
URL = 'https://api.nodequality.com/api/v1/record'
POST = ['-X', 'POST', '--data-binary', '@-', URL]


def report_data():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('header_info.log', 'Private inert report fixture.\n')
        archive.writestr('hardware_quality.log', 'No benchmark executed.\n')
    return base64.b64encode(stream.getvalue())


class UploadBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='sinan-upload-boundary-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.curl_trace = self.root / 'curl.json'
        real = self.root / 'curl'
        real.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
pathlib.Path(os.environ['FIXTURE_CURL_TRACE']).write_text(json.dumps(sys.argv[1:]))
sys.stdout.write('https://nodequality.com/r/private-fixture\\nSINAN_RESPONSE_STATUS:200')
raise SystemExit(int(os.environ.get('FIXTURE_CURL_STATUS', '0')))
''')
        real.chmod(0o700)
        self.environment = dict(os.environ, SINAN_REPORT_WORKSPACE=str(self.root),
                                SINAN_REPORT_HELPER=str(PLUGIN / 'report.py'),
                                SINAN_REAL_CURL=str(real), FIXTURE_CURL_TRACE=str(self.curl_trace))
        self.environment.pop('SINAN_UPLOAD_REPORT', None)
        self.data = report_data()

    def shim(self, arguments=POST, permission=None, status=0):
        environment = dict(self.environment, FIXTURE_CURL_STATUS=str(status))
        if permission is not None:
            environment['SINAN_UPLOAD_REPORT'] = permission
        return subprocess.run(['bash', str(PLUGIN / 'runtime-curl.sh'), *arguments],
                              env=environment, input=self.data, capture_output=True, timeout=4)

    def test_default_false_and_unknown_permission_keep_the_local_report_without_network(self):
        for permission in (None, 'false', 'yes'):
            with self.subTest(permission=permission):
                result = self.shim(permission=permission)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.root / 'upload.base64').read_bytes(), self.data)
                self.assertTrue((self.root / 'section-header_info.json').is_file())
                self.assertTrue((self.root / 'upload-disabled.txt').is_file())
                self.assertFalse(self.curl_trace.exists())

    def test_explicit_true_uses_one_https_destination_and_ignores_curlrc(self):
        curlrc = self.root / '.curlrc'
        curlrc.write_text('url = "https://unapproved.invalid/collect"\nretry = 99\n')
        self.environment['CURL_HOME'] = str(self.root)
        result = self.shim(permission='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.curl_trace.read_text())
        self.assertEqual(arguments[0], '--disable')
        self.assertEqual([value for value in arguments if value.startswith('https://')], [URL])
        self.assertEqual(arguments[arguments.index('--proto') + 1], '=https')
        self.assertEqual(arguments[arguments.index('--proto-redir') + 1], '=https')
        self.assertNotIn('--location', arguments)
        self.assertNotIn('--retry', arguments)
        self.assertEqual(arguments[arguments.index('--data-binary') + 1], '@' + str(self.root / 'upload.base64'))
        self.assertEqual((self.root / 'upload.base64').read_bytes(), self.data)
        self.assertEqual((self.root / 'upload-status.txt').read_bytes(), b'200')

    def test_extra_destinations_configs_file_inputs_and_methods_are_rejected_before_capture(self):
        for arguments in (POST + ['https://unapproved.invalid/collect'],
                          ['https://unapproved.invalid/collect'] + POST,
                          POST + [URL], POST + ['--next', URL],
                          POST + ['--config', '/PRIVATE/curlrc'],
                          POST + ['--location'], POST + ['--retry', '99'],
                          ['-X', 'POST', '--data-binary', '@/PRIVATE/data', URL],
                          ['-X', 'GET', '--data-binary', '@-', URL],
                          [URL], ['--url', URL]):
            for permission in ('false', 'true'):
                with self.subTest(arguments=arguments, permission=permission):
                    result = self.shim(arguments, permission)
                    self.assertEqual(result.returncode, 70, result.stderr)
                    self.assertIn(b'unsupported public report request', result.stderr)
                    self.assertFalse((self.root / 'upload.base64').exists())
                    self.assertFalse(self.curl_trace.exists())

    def test_transport_failure_is_preserved_after_local_report_capture(self):
        result = self.shim(permission='true', status=28)
        self.assertEqual(result.returncode, 28, result.stderr)
        self.assertEqual((self.root / 'upload.base64').read_bytes(), self.data)
        self.assertTrue((self.root / 'section-header_info.json').is_file())


if __name__ == '__main__':
    unittest.main()
