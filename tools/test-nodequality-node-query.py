#!/usr/bin/env python3
"""Offline official-node adapter contracts; no network or real credentials."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('node_query', ROOT / 'plugins/nodequality/node-query.py')
query = importlib.util.module_from_spec(spec)
spec.loader.exec_module(query)
KEY = 'TEST_ONLY_private_api_credential_12345'
JOB = '00000000-0000-4000-8000-000000000042'


class NodeQueryContracts(unittest.TestCase):
    def body(self, provider, ip='1.1.1.1'):
        if provider == 'ipregistry-node':
            return {'ip': ip, 'type': 'IPv6' if ':' in ip else 'IPv4',
                    'connection': {'asn': 13335}, 'security': {'is_proxy': False}}
        return {'ipAddress': ip, 'latitude': 0, 'isProxy': False}

    def configured(self):
        return {provider: (KEY, None) for provider in query.PROVIDERS}

    def execute(self, answer, ips=None, version='both', configured=None):
        with tempfile.TemporaryDirectory(prefix='sinan-node-query-contract-') as directory:
            workspace = Path(directory).resolve()
            source = workspace / 'node-ips.json'
            source.write_text(json.dumps(ips or ['1.1.1.1']))
            source.chmod(0o600)
            receipts = []
            original = query.atomic
            def capture(path, data):
                original(path, data)
                if path.name == 'section-ip_quality.json':
                    receipts.append(json.loads(data))
            with patch.object(query, 'load_configuration', return_value=configured or self.configured()), \
                 patch.object(query, 'curl_json', side_effect=answer) as requests, \
                 patch.object(query, 'atomic', side_effect=capture):
                query.run(workspace, source, version, JOB)
            return json.loads(receipts[-1]['text']), receipts, requests.call_args_list, (workspace / 'result.txt').read_text()

    def curl(self, raw, code=0, provider='dbip-node', environment=None, read_failure=False):
        actual = subprocess.Popen
        captured = {}
        original_read = os.read
        def read(descriptor, size):
            if read_failure and descriptor == captured.get('stdout_fd'):
                raise OSError(KEY)
            return original_read(descriptor, size)
        script = 'import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(' + repr(raw) + '); sys.exit(' + str(code) + ')'
        def spawn(arguments, **kwargs):
            captured['args'], captured['env'] = arguments, kwargs['env']
            process = actual([sys.executable, '-c', script], **kwargs)
            captured['stdout_fd'] = process.stdout.fileno()
            original = process.stdin
            class Input:
                @property
                def closed(self): return original.closed
                def write(self, data):
                    captured['stdin'] = data
                    return original.write(data)
                def close(self): original.close()
            process.stdin = Input()
            return process
        # Start from the host environment without its own proxy settings (for example a
        # developer's YARN_HTTPS_PROXY), so only the variables injected here are judged.
        ambient = {name: value for name, value in os.environ.items() if not name.lower().endswith('proxy')}
        with patch.object(query.subprocess, 'Popen', side_effect=spawn), \
             patch.dict(os.environ, {**ambient, **(environment or {})}, clear=True), \
             patch.object(query.os, 'read', side_effect=read):
            try:
                value = query.curl_json(provider, KEY, 'self', 4, time.monotonic() + 75)
                return value, captured
            except query.QueryFailure as error:
                error.captured = captured
                raise

    def test_native_curl_secret_stdin_and_no_proxy_retry_ua_or_redirect(self):
        for provider in query.PROVIDERS:
            value, captured = self.curl(json.dumps(self.body(provider)).encode() + b'\n200', provider=provider,
                                       environment={'HTTP_PROXY': 'TEST_ONLY_proxy', 'https_proxy': 'TEST_ONLY_proxy',
                                                    'SINAN_SECRET': KEY, 'CURL_CA_BUNDLE': 'TEST_ONLY_alternate_CA',
                                                    'SSL_CERT_FILE': 'TEST_ONLY_alternate_CA',
                                                    'SSL_CERT_DIR': 'TEST_ONLY_alternate_CA',
                                                    'SSLKEYLOGFILE': 'TEST_ONLY_tls_secrets', 'QLOGDIR': 'TEST_ONLY_logs'})
            self.assertIsInstance(value, dict)
            self.assertEqual(captured['args'], ['/usr/bin/curl', '--disable', '--config', '-'])
            self.assertNotIn(KEY, repr(captured['args']))
            self.assertNotIn(KEY, repr(captured['env']))
            self.assertFalse(any(name.lower().endswith('proxy') for name in captured['env']))
            self.assertFalse(query.REQUEST_ENV_BLOCKED & {name.lower() for name in captured['env']})
            config = captured['stdin'].decode()
            self.assertIn(KEY, config)
            self.assertIn('retry = 0', config)
            self.assertIn('max-redirs = 0', config)
            self.assertIn('max-time = 6', config)
            self.assertNotIn('user-agent', config)
            self.assertNotIn('location', config)
            self.assertNotIn('insecure', config)

    def test_http_and_transport_failures_are_sanitized(self):
        for status, kind in [(401, 'http_other'), (403, 'http_403'), (429, 'http_429'), (302, 'http_other')]:
            with self.subTest(status=status), self.assertRaises(query.QueryFailure) as caught:
                self.curl((KEY + '\n' + str(status)).encode())
            self.assertEqual(caught.exception.kind, kind)
            self.assertEqual(caught.exception.http_status, status)
            self.assertNotIn(KEY, str(caught.exception))

        for code, kind in [(6, 'dns'), (7, 'connect'), (28, 'timeout'), (35, 'tls'), (60, 'tls'), (63, 'response_limit')]:
            with self.subTest(code=code), self.assertRaises(query.QueryFailure) as caught:
                self.curl(b'', code=code)
            self.assertEqual(caught.exception.kind, kind)
            self.assertNotIn(KEY, str(caught.exception))

    def test_response_pipe_failure_is_a_sanitized_per_source_error(self):
        with self.assertRaises(query.QueryFailure) as caught:
            self.curl(b'{}\n200', read_failure=True)
        self.assertEqual(caught.exception.kind, 'body_error')
        self.assertNotIn(KEY, str(caught.exception))

    def test_missing_invalid_and_explicit_failure_json_are_unknown(self):
        for raw in [b'{"ipAddress":"1.1.1.1","ipAddress":"8.8.8.8"}\n200', b'{"latitude":NaN}\n200']:
            with self.assertRaises(query.QueryFailure): self.curl(raw)
        for body in [None, [], {}, {'success': False, 'ipAddress': '1.1.1.1'}, {'errorCode': 'AUTH'},
                     {'status': 'failed'}, {'errors': [{'message': KEY}]}]:
            with self.subTest(body=body):
                if body == {}:
                    value, _ = self.curl(b'{}\n200')
                    with self.assertRaises(query.QueryFailure): query.identity('dbip-node', value, 4)
                else:
                    with self.assertRaises(query.QueryFailure): self.curl(json.dumps(body).encode() + b'\n200')
        with self.assertRaises(query.QueryFailure) as caught:
            self.curl(b'x' * (query.BODY_LIMIT + 1) + b'\n200')
        self.assertEqual(caught.exception.kind, 'response_limit')

    def test_official_fields_preserve_false_zero_and_reject_wrong_types(self):
        data = query.whitelisted_data('dbip-node', self.body('dbip-node'))
        self.assertIs(data['isProxy'], False)
        self.assertEqual(data['latitude'], 0)
        for wrong in [0, 'false', [], {}]:
            with self.subTest(wrong=wrong), self.assertRaises(query.QueryFailure):
                query.whitelisted_data('dbip-node', {'isProxy': wrong})
        with self.assertRaises(query.QueryFailure): query.whitelisted_data('dbip-node', {'asNumber': False})
        self.assertNotIn('isp', query.whitelisted_data('dbip-node', {'isp': KEY}, KEY))
        self.assertNotIn('api_key', query.whitelisted_data('dbip-node', {'api_key': KEY}, KEY))
        self.assertEqual(query.whitelisted_data('dbip-node', {'isProxy': None}), {})

    def test_origin_mismatch_never_queries_frozen_panel_target(self):
        report, _, calls, _ = self.execute(lambda provider, key, target, family, deadline: self.body(provider, '8.8.8.8'))
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call.args[2] == 'self' for call in calls))
        self.assertTrue(all(row['data'] is None and row['observed_ip'] == '8.8.8.8' for row in report['results']))
        self.assertTrue(all(row['error']['kind'] == 'schema_mismatch' for row in report['results']))

    def test_real_origin_then_target_each_family_and_partial_atomic_report(self):
        def answer(provider, key, target, family, deadline):
            return self.body(provider, '1.1.1.1' if family == 4 else '2606:4700:4700::1111')
        report, receipts, calls, text = self.execute(answer, ['1.1.1.1', '2606:4700:4700::1111'])
        self.assertEqual(len(calls), 8)
        self.assertEqual([call.args[2] for call in calls], ['self', '1.1.1.1', 'self', '2606:4700:4700::1111'] * 2)
        self.assertEqual([receipt['revision'] for receipt in receipts], list(range(1, 7)))
        self.assertFalse(receipts[0]['complete'])
        self.assertTrue(receipts[-1]['complete'])
        self.assertTrue(all(row['data'] and row['error'] is None and row['execution'] == 'node' for row in report['results']))
        self.assertEqual(report['streaming']['status'], 'unknown')
        self.assertIn('Disney+', text)
        self.assertNotIn(KEY, json.dumps(receipts) + text)

    def test_missing_credentials_do_not_call_and_keep_per_source_reason(self):
        configured = {provider: (None, 'TEST_ONLY 未配置正式授权，信息未知') for provider in query.PROVIDERS}
        report, _, calls, _ = self.execute(lambda *args: self.fail('no network without configuration'), configured=configured)
        self.assertEqual(calls, [])
        self.assertTrue(all(not row['available'] and row['attempted_at'] is None and row['error']['kind'] == 'not_attempted' for row in report['results']))

    def test_family_selection_and_invalid_identity(self):
        report, _, calls, _ = self.execute(lambda provider, key, target, family, deadline: self.body(provider),
            ['1.1.1.1', '2606:4700:4700::1111'], 'ipv4')
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(call.args[3] == 4 for call in calls))
        self.assertTrue(all(row['attempted_at'] is None for row in report['results'] if ':' in row['target_ip']))
        for ip in ['127.0.0.1', '192.0.2.1', '224.0.0.1', '100.64.0.1', '::1', '2001:db8::1',
                   '192.88.99.1', '192.88.99.2', '2001:2::1', '3fff::1', '3fff:fff::1']:
            with self.subTest(ip=ip), self.assertRaises(ValueError): query.public_ip(ip)
        with self.assertRaises(query.QueryFailure): query.identity('ipregistry-node', {'ip': '1.1.1.1', 'type': 'IPv6'}, 4)

    def test_special_use_frozen_inputs_never_start_provider_requests(self):
        with tempfile.TemporaryDirectory(prefix='sinan-node-query-special-input-') as directory:
            workspace = Path(directory).resolve()
            source = workspace / 'node-ips.json'
            for ip in ['192.88.99.2', '2001:2::1', '3fff::1']:
                source.write_text(json.dumps([ip]))
                with self.subTest(ip=ip), patch.object(query, 'curl_json') as requests, \
                     patch.object(query, 'load_configuration', return_value=self.configured()), \
                     self.assertRaises(ValueError):
                    query.run(workspace, source, 'both', JOB)
                requests.assert_not_called()

    def test_frozen_input_refuses_symlink_directory_and_oversized_file(self):
        with tempfile.TemporaryDirectory(prefix='sinan-node-query-input-') as directory:
            workspace = Path(directory).resolve()
            source = workspace / 'node-ips.json'
            target = workspace / 'other.json'
            target.write_text('["1.1.1.1"]')
            source.symlink_to(target)
            with self.assertRaises(OSError):
                query.frozen_ips(workspace, source, time.monotonic() + 3)
            source.unlink()
            source.mkdir()
            with self.assertRaises(ValueError):
                query.frozen_ips(workspace, source, time.monotonic() + 3)
            source.rmdir()
            source.write_bytes(b' ' * 2049)
            with self.assertRaises(ValueError):
                query.frozen_ips(workspace, source, time.monotonic() + 3)

    def test_real_fifo_frozen_input_is_rejected_before_any_provider_request(self):
        with tempfile.TemporaryDirectory(prefix='sinan-node-query-input-fifo-') as directory:
            workspace = Path(directory).resolve()
            source = workspace / 'node-ips.json'
            os.mkfifo(source, mode=0o600)
            result = subprocess.run([sys.executable, str(ROOT / 'plugins/nodequality/node-query.py'),
                                     '--workspace', str(workspace), '--ips-file', str(source),
                                     '--ip-version', 'both', '--job-id', JOB],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('私有输入或报告写入失败', result.stderr)
            self.assertFalse((workspace / 'section-ip_quality.json').exists())

    def test_config_contract_private_authorized_only_and_permission_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'credentials.json'
            original = os.fstat
            def fileinfo(descriptor):
                result = original(descriptor)
                return types.SimpleNamespace(st_uid=0, st_mode=result.st_mode, st_size=result.st_size)
            parent = types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
            with patch.object(query, 'CONFIG', path), patch.object(Path, 'lstat', return_value=parent), \
                 patch.object(query.os, 'fstat', side_effect=fileinfo):
                missing = query.load_configuration()
                self.assertTrue(all(item[0] is None for item in missing.values()))
                for item in [{'api_key': KEY, 'authorized': True}, {'api_key': KEY, 'authorized': False},
                             {'api_key': 'YOUR_API_KEY', 'authorized': True}, {'api_key': KEY, 'authorized': True, 'endpoint': 'https://invalid.test'}]:
                    path.write_text(json.dumps({'schema': query.CONFIG_SCHEMA, 'providers': {'dbip-node': item}}))
                    path.chmod(0o600)
                    value = query.load_configuration()
                    self.assertEqual(value['dbip-node'][0] is not None, item == {'api_key': KEY, 'authorized': True})
                path.chmod(0o644)
                self.assertTrue(all(item[0] is None for item in query.load_configuration().values()))

    def test_real_fifo_configuration_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory(prefix='sinan-node-query-fifo-') as directory:
            path = Path(directory) / 'credentials.json'
            os.mkfifo(path, mode=0o600)
            script = '''
import importlib.util, json, os, stat, sys, types
from pathlib import Path
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('fifo_query', sys.argv[1])
query = importlib.util.module_from_spec(spec)
spec.loader.exec_module(query)
query.CONFIG = Path(sys.argv[2])
original = os.fstat
def fileinfo(descriptor):
    info = original(descriptor)
    return types.SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_size=info.st_size)
parent = types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
with patch.object(Path, 'lstat', return_value=parent), patch.object(query.os, 'fstat', side_effect=fileinfo):
    print(json.dumps(query.load_configuration()))
'''
            # Preserve the existing root/stat fixture contract, but open a real
            # owned FIFO with no writer in a bounded, independently reaped child.
            result = subprocess.run([sys.executable, '-c', script, str(ROOT / 'plugins/nodequality/node-query.py'), str(path)],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            configured = json.loads(result.stdout)
            self.assertEqual(set(configured), set(query.PROVIDERS))
            for key, reason in configured.values():
                self.assertIsNone(key)
                self.assertIn('无法安全读取或校验', reason)
                self.assertIn('未执行查询', reason)
                self.assertIn('信息未知', reason)

    def test_failure_source_does_not_erase_other_source_partial_success(self):
        def answer(provider, *args):
            if provider == 'dbip-node': raise query.QueryFailure('http_429', 'TEST_ONLY 限流，信息未知', 429)
            return self.body(provider)
        report, receipts, _, _ = self.execute(answer)
        self.assertIsNone(report['results'][0]['error'])
        self.assertEqual(report['results'][1]['error']['kind'], 'http_429')
        self.assertTrue(receipts[-1]['complete'])


if __name__ == '__main__': unittest.main()
