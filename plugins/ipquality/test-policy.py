#!/usr/bin/env python3
"""Offline fixtures for the standalone source closure and real request guard."""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SOURCE_CACHE = None
EXAMPLE_IP = '192.0.2.1'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


transport = module('sinan_ipquality_transport_fixture', HERE / 'transport.py')
helper = module('sinan_ipquality_source_fixture', HERE / 'source-helper.py')
policy = module('sinan_ipquality_policy_fixture', HERE / 'source-policy.py')


def documentation_fixture_ip(value, family=None):
    # Synthetic provider fixtures use a reserved documentation address. Only
    # these schema fixtures bypass the public check; production never does.
    import ipaddress
    address = ipaddress.ip_address(value.strip())
    if family and address.version != int(family):
        raise ValueError('fixture family mismatch')
    return str(address)


class SourceClosureTests(unittest.TestCase):
    def test_developer_fallback_uses_exact_reviewed_native_media_helpers(self):
        policies = helper.policy_bytes()
        node = HERE.parent / 'nodequality'
        for name in ('browser', 'netflix'):
            reviewed = (node / ('native-' + name + '-policy.py')).read_bytes()
            self.assertEqual(policies[name], reviewed)
            self.assertEqual(hashlib.sha256(reviewed).hexdigest(), helper.POLICIES[name])
            self.assertNotEqual(policies[name], (node / (name + '-policy.py')).read_bytes())

    def test_wrong_generic_media_helper_is_rejected_without_changing_reviewed_digest(self):
        with tempfile.TemporaryDirectory(prefix='sinan-ipquality-policy-closure-') as name:
            root = Path(name)
            here, shared = root / 'ipquality', root / 'nodequality'
            here.mkdir()
            shared.mkdir()
            actual = helper.policy_bytes()
            for role, content in actual.items():
                filename = helper.REVIEWED_POLICY_FILES.get(role, role + '-policy.py')
                (shared / filename).write_bytes(content)
            with mock.patch.object(helper, '__file__', str(here / 'source-helper.py')):
                self.assertEqual(helper.policy_bytes(), actual)
                for role in ('browser', 'netflix'):
                    path = shared / helper.REVIEWED_POLICY_FILES[role]
                    path.write_bytes((HERE.parent / 'nodequality' / (role + '-policy.py')).read_bytes())
                    with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'identity mismatch: ' + role):
                        helper.policy_bytes()
                    path.write_bytes(actual[role])

    def test_published_role_filenames_use_exact_copies_and_do_not_fall_back_on_mismatch(self):
        with tempfile.TemporaryDirectory(prefix='sinan-ipquality-policy-offer-') as name:
            here = Path(name) / 'ipquality'
            policies = here / 'policies'
            policies.mkdir(parents=True)
            actual = helper.policy_bytes()
            for role, content in actual.items():
                (policies / (role + '-policy.py')).write_bytes(content)
            with mock.patch.object(helper, '__file__', str(here / 'source-helper.py')):
                self.assertEqual(helper.policy_bytes(), actual)
                (policies / 'browser-policy.py').write_bytes(b'TEST_ONLY unreviewed helper')
                with self.assertRaisesRegex(ValueError, 'identity mismatch: browser'):
                    helper.policy_bytes()

    def test_exact_roles_and_full_license_are_required(self):
        lock = helper.canonical_lock()
        self.assertEqual(set(helper.validate(lock)), {'ip.sh', 'LICENSE.ip', 'ip-iso3166.json', 'ip-dnsbl.list'})
        for field, replacement in (('commit', 'main'), ('sha256', '0' * 64), ('size', 1), ('repository', 'example/other')):
            changed = json.loads(json.dumps(lock))
            changed['files'][0][field] = replacement
            with self.assertRaises(ValueError):
                helper.validate(changed)

    def test_missing_and_duplicate_source_roles_are_rejected(self):
        for lock in (dict(schema=1, files=helper.canonical_lock()['files'][:-1]),
                     dict(schema=1, files=[helper.canonical_lock()['files'][0]] * 4)):
            with self.assertRaises(ValueError):
                helper.validate(lock)

    def test_source_checksums_are_required_without_executing_source(self):
        with self.assertRaises(ValueError):
            helper.transform_files({name: b'#!/bin/bash\nexit 0\n' for name in helper.EXPECTED})
        with self.assertRaises(ValueError):
            policy.transform(b'#!/bin/bash\nexit 0\n', {}, {})

    def test_bundle_duplicate_keys_and_extra_roles_are_rejected(self):
        with self.assertRaises(ValueError):
            helper.decode_bundle(b'{"schema":1,"schema":1,"lock":{},"files":{}}')
        with self.assertRaises(ValueError):
            helper.bundle_files(dict(schema=1, lock=helper.canonical_lock(), files=dict(extra=base64.b64encode(b'x').decode())))

    def test_dnsbl_replacement_consumes_nested_pipeline_and_preserves_next_function(self):
        ending = b'echo "${smail[t]} ${smail[c]} ${smail[m]} ${smail[b]}"\n}\n}\n'
        following = b'declare -A preserved_global=()\ncheck_dnsbl(){\n: # next function\n}\n'
        original = b'check_dnsbl_parallel(){\nprintf ignored |{\n:\n' + ending + following
        replacement = policy.SIMPLE_FUNCTIONS['check_dnsbl_parallel'].encode()
        self.assertEqual(policy.replace_function(original, 'check_dnsbl_parallel', replacement),
                         replacement + following)
        with self.assertRaises(ValueError):
            policy.replace_function(original.replace(ending, b'echo unexpected\n}\n}\n'),
                                    'check_dnsbl_parallel', replacement)

    def test_ad_replacement_consumes_both_nested_functions_and_preserves_global(self):
        original = (b'show_ad(){\nprint_pair(){\n:\n}\nprint_block(){\n:\n}\n'
                    b'if true;then\n:\nelse\nADLines=$(((adCount+1)*12))\nfi\n}\n')
        following = b'declare -A preserved_global=()\nread_ref(){\n: # next function\n}\n'
        replacement = policy.SIMPLE_FUNCTIONS['show_ad'].encode()
        self.assertEqual(policy.replace_function(original + following, 'show_ad', replacement),
                         replacement + following)
        # A missing outer marker must not consume a later function's ending.
        wrong_neighbor = (b'declare -A preserved_global=()\nread_ref(){\nif true;then\n:\nelse\n'
                          b'ADLines=$(((adCount+1)*12))\nfi\n}\n')
        with self.assertRaises(ValueError):
            policy.replace_function(original.replace(b'ADLines=$(((adCount+1)*12))', b'changed') + wrong_neighbor,
                                    'show_ad', replacement)

    def test_json_quotes_continue_after_multiline_literal_and_preserve_globals(self):
        before = b'save_json(){\nlocal literal=\'{\n}\n\'\n'
        field = b'head_updates+=".Head |= . + { IP: \\"${IP:-null}\\" } | "\n'
        ending = (b'ipjson=$(printf \'%s\' "$ipjson"|jq --argjson registry "${ipregistry[access]:-null}" '
                  b'--argjson dbip "${dbip[access]:-null}" --argjson disney "${disney[access]:-null}" '
                  b'--argjson youtube "${youtube[access]:-null}" \'.Sources=(.Sources//{}) | '
                  b'.Sources.ipregistry=$registry | .Sources.DBIP=$dbip | .Media.DisneyPlus += $disney | '
                  b'.Media.Youtube += $youtube\')\n}\n')
        following = b'declare -A preserved_global=()\ncheck_IP(){\n: # next function\n}\n'
        quoted = b'head_updates+=".Head |= . + { IP: $(sinan_node_json_text "${IP:-null}") } | "\n'
        self.assertEqual(policy.quote_json_values(before + field + ending + following),
                         before + quoted + ending + following)

    def test_actual_pinned_source_has_valid_complete_bash_syntax(self):
        if SOURCE_CACHE is None:
            self.skipTest('requires local exact four-role upstream cache; does not download sources')
        files = {name: (SOURCE_CACHE / name).read_bytes() for name in helper.EXPECTED}
        transformed = helper.transform_files(files)['patched-ip.sh']
        bash = os.environ.get('SINAN_IPQUALITY_TEST_BASH',
                              os.environ.get('SINAN_NODEQUALITY_TEST_BASH', '/bin/bash'))
        with tempfile.TemporaryDirectory(prefix='sinan-ipquality-syntax-') as directory:
            path = Path(directory) / 'patched-ip.sh'
            path.write_bytes(transformed)
            result = subprocess.run([bash, '-n', str(path)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_actual_pinned_source_has_independent_final_main(self):
        if SOURCE_CACHE is None:
            self.skipTest('requires local exact four-role upstream cache; does not download sources')
        files = {name: (SOURCE_CACHE / name).read_bytes() for name in helper.EXPECTED}
        transformed = helper.transform_files(files)
        script = transformed['patched-ip.sh']
        self.assertTrue(script.startswith(b'#!/bin/bash\n'))
        final_main = script[script.index(b'# The independently signed wrapper supplies'):]
        self.assertIn(b'[[ $# == 1 && ( $1 == 4 || $1 == 6 ) ]]', final_main)
        for forbidden in (b'get_opts', b'show_ad', b'countRunTimes', b'read_ref', b'check_connectivity', b'upload.check.place'):
            self.assertNotIn(forbidden, final_main)
        self.assertIn(b'SMTP / DNSBL', script)
        self.assertIn(b'sinan_ip_score_json "${ipqs[score]:-}"', script)
        self.assertNotIn(b'score_updates+=".Score |= . + { IPQS: \\"${ipapi[ipqs]', script)
        self.assertIn(b'$(sinan_node_json_text "${maxmind[org]:-null}")', script)
        self.assertEqual(transformed['LICENSE.ip'], files['LICENSE.ip'])

    def test_actual_upstream_serializer_treats_organization_as_data_and_unknown_factor_as_null(self):
        if SOURCE_CACHE is None:
            self.skipTest('requires local exact four-role upstream cache; does not download sources')
        bash = os.environ.get('SINAN_IPQUALITY_TEST_BASH', os.environ.get('SINAN_NODEQUALITY_TEST_BASH', '/bin/bash'))
        if int(subprocess.check_output([bash, '-c', 'printf "%s" "${BASH_VERSINFO[0]}"'], text=True)) < 4:
            self.skipTest('the fixed upstream profile requires Bash >= 4; production Debian uses Bash 5')
        if not shutil.which('jq'):
            self.skipTest('actual upstream JSON serialization requires offline jq')
        files = {name: (SOURCE_CACHE / name).read_bytes() for name in helper.EXPECTED}
        transformed = helper.transform_files(files)['patched-ip.sh']
        definitions = transformed[:transformed.index(b'# The independently signed wrapper supplies')]
        harness = r'''
set_language
IP=$FIXTURE_IP;fullIP=1;mode_lite=0
maxmind[org]=$FIXTURE_ORG
scamalytics[countrycode]='"|'
ipapi[ipqs]=99
ipqs[score]=0
ipjson='{"Head":{},"Info":{},"Type":{},"Score":{},"Factor":{},"Media":{},"Mail":{}}'
save_json || exit 70
printf '%s' "$ipjson"
'''.encode()
        organization = 'fixture " | error("provider data must not execute") | " \\ suffix'
        with tempfile.TemporaryDirectory(prefix='sinan-ipquality-serializer-') as directory:
            path = Path(directory) / 'serializer.sh'
            path.write_bytes(definitions + harness)
            result = subprocess.run([bash, str(path)], capture_output=True, timeout=15,
                                    env={**os.environ, 'FIXTURE_IP': EXAMPLE_IP, 'FIXTURE_ORG': organization})
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        data = json.loads(result.stdout)
        self.assertEqual(data['Info']['Organization'], organization)
        self.assertEqual(data['Score']['IPQS'], '0')
        self.assertIsNone(data['Factor']['CountryCode']['SCAMALYTICS'])
        self.assertIsNone(data['Mail']['Port25'])
        self.assertIsNone(data['Mail']['DNSBlacklist']['Clean'])


class RequestGuardTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix='sinan-ipquality-guard-')
        self.directory = Path(self.workspace.name)
        self.receipts = self.directory / 'attempts.jsonl'
        self.environment = mock.patch.dict(os.environ, {
            'SINAN_IPQUALITY_FAMILY': '4', 'SINAN_IPQUALITY_TARGET_IP': EXAMPLE_IP,
            'SINAN_IPQUALITY_ATTEMPTS': str(self.receipts),
            'SINAN_IPQUALITY_PARTIAL': str(self.directory / 'partial.json'),
        })
        self.environment.start()
        self.public_fixture = mock.patch.object(transport, 'canonical_ip', side_effect=documentation_fixture_ip)
        self.public_fixture.start()

    def tearDown(self):
        self.public_fixture.stop()
        self.environment.stop()
        self.workspace.cleanup()

    def captured(self, body, status=200, code=0, category=None):
        return body + transport.MARKER + f'{status:03}|0.001|application/json|\n'.encode(), code, category

    def request(self, body, status=200, code=0, category=None, dataset='ipqualityscore'):
        suffix = '?lang=en' if dataset == 'MaxMind' else '?db=' + dataset
        url = 'https://ipinfo.check.place/' + EXAMPLE_IP + suffix
        with (mock.patch.object(transport, 'capture', return_value=self.captured(body, status, code, category)) as capture,
              mock.patch.object(sys, 'stdout', new=io.TextIOWrapper(io.BytesIO(), encoding='utf-8'))):
            result = transport.request(['-q', '-sL', '-4', '-m', '10', url])
        return result, transport.load_receipts(self.receipts)[-1], capture

    def test_http_403_and_429_are_recorded_without_retry_or_body(self):
        for status, kind in ((403, 'http_403'), (429, 'http_429')):
            result, row, capture = self.request(b'{"fraud_score":0,"country_code":"ZZ"}', status=status)
            self.assertNotEqual(result, 0)
            self.assertEqual(row['error_kind'], kind)
            self.assertEqual(row['http_status'], status)
            self.assertEqual(row['status'], 'failed')
            self.assertEqual(capture.call_count, 1)

    def test_dns_connect_tls_timeout_are_classified(self):
        for code, kind in ((6, 'dns'), (7, 'connect'), (60, 'tls'), (28, 'timeout')):
            result, row, _capture = self.request(b'', status=0, code=code)
            self.assertNotEqual(result, 0)
            self.assertEqual(row['error_kind'], kind)
            self.assertIsNone(row['http_status'])

    def test_non_json_schema_mismatch_and_legitimate_zero_remain_distinct(self):
        cases = ((b'<html>error</html>', 'non_json'), (b'{}', 'schema_mismatch'),
                 (b'{"fraud_score":"0","country_code":"ZZ"}', 'schema_mismatch'),
                 (b'{"success":false,"fraud_score":0,"country_code":"ZZ"}', 'schema_mismatch'),
                 (b'{"fraud_score":0,"country_code":"ZZ"}', None))
        for body, kind in cases:
            result, row, _capture = self.request(body)
            self.assertEqual(row['error_kind'], kind)
            self.assertEqual(result == 0, kind is None)

    def test_http_400_with_zero_score_and_false_flags_is_unknown(self):
        result, row, capture = self.request(b'{"fraud_score":0,"country_code":"ZZ","proxy":false}', status=400)
        self.assertNotEqual(result, 0)
        self.assertEqual(row['status'], 'failed')
        self.assertEqual(row['error_kind'], 'http_other')
        self.assertEqual(row['http_status'], 400)
        self.assertEqual(capture.call_count, 1)

    def test_deep_overflow_and_surrogate_json_keep_failure_receipts(self):
        bodies = [b'{"fraud_score":0,"country_code":"ZZ","nested":' + b'[' * 1500 + b'0' + b']' * 1500 + b'}',
                  b'{"fraud_score":0,"country_code":"ZZ","remark":"\\ud800"}']
        for body in bodies:
            result, row, capture = self.request(body)
            self.assertNotEqual(result, 0)
            self.assertEqual(row['error_kind'], 'schema_mismatch')
            self.assertEqual(row['response_bytes'], len(body))
            self.assertEqual(capture.call_count, 1)
        body = b'{"ASN":{},"Country":{"IsoCode":"ZZ"},"City":{"Latitude":' + b'1' + b'0' * 1000 + b'}}'
        result, row, capture = self.request(body, dataset='MaxMind')
        self.assertNotEqual(result, 0)
        self.assertEqual(row['error_kind'], 'schema_mismatch')
        self.assertEqual(row['provider'], 'check-place-aggregator')
        self.assertEqual(row['response_bytes'], len(body))
        self.assertEqual(capture.call_count, 1)

    def test_country_code_and_consumed_scalar_types_are_validated(self):
        for value in (False, True, 12, ['ZZ'], {'country': 'ZZ'}, '12', '"|'):
            body = json.dumps({'fraud_score': 0, 'country_code': value}).encode()
            result, row, _ = self.request(body)
            self.assertNotEqual(result, 0)
            self.assertEqual(row['error_kind'], 'schema_mismatch')
            scamalytics = {'scamalytics': {'scamalytics_score': 0},
                           'external_datasources': {'maxmind_geolite2': {'ip_country_code': value}}}
            result, row, _ = self.request(json.dumps(scamalytics).encode(), dataset='scamalytics')
            self.assertNotEqual(result, 0)
            self.assertEqual(row['error_kind'], 'schema_mismatch')
        body = b'{"ASN":{"AutonomousSystemOrganization":false},"Country":{"IsoCode":"ZZ"}}'
        result, row, _ = self.request(body, dataset='MaxMind')
        self.assertNotEqual(result, 0)
        self.assertEqual(row['error_kind'], 'schema_mismatch')

    def test_legacy_annotation_aliases_preserve_evidence(self):
        for alias, normalized in (('connection', 'connect'), ('http_status', 'http_other'),
                                  ('empty_response', 'schema_mismatch'), ('response_too_large', 'response_limit'),
                                  ('reader_error', 'request_error'), ('incomplete_response', 'request_error'),
                                  ('invalid_response', 'schema_mismatch'), ('transport', 'request_error')):
            self.request(b'{"fraud_score":0,"country_code":"ZZ"}')
            transport.annotate('IPQS', alias, '页面信息未知')
            row = transport.load_receipts(self.receipts)[-1]
            self.assertEqual(row['status'], 'failed')
            self.assertEqual(row['error_kind'], normalized)
            self.assertEqual(row['http_status'], 200)
            self.assertEqual(row['curl_exit'], 0)

    def test_duplicate_fields_wrong_target_and_awk_payload_are_rejected(self):
        bodies = ((b'{"fraud_score":0,"fraud_score":1,"country_code":"ZZ"}', 'ipqualityscore'),
                  (b'{"fraud_score":0,"country_code":"ZZ","ip":"192.0.2.2"}', 'ipqualityscore'),
                  (b'{"data":{"asn":{},"country":"ZZ","loc":"system(command),0"}}', None))
        for body, dataset in bodies:
            if dataset:
                result, row, _capture = self.request(body, dataset=dataset)
                self.assertNotEqual(result, 0)
                self.assertIsNotNone(row['error_kind'])
            else:
                kind, _ = transport.validate_body('ipinfo-public-widget', 'IPinfo', body, EXAMPLE_IP, '4')
                self.assertEqual(kind, 'schema_mismatch')

    def test_unknown_endpoint_identity_headers_retries_and_insecure_are_rejected_before_io(self):
        for arguments in (['https://example.invalid/'], ['-k', 'https://ident.me/'],
                          ['--retry', '3', 'https://ident.me/'], ['--user-agent', 'browser', 'https://ident.me/'],
                          ['-H', 'Authorization: secret', 'https://ident.me/'],
                          ['-H', 'Cookie: secret', 'https://ident.me/'],
                          ['-6', 'https://ident.me/']):
            with mock.patch.object(transport, 'capture') as capture:
                with self.assertRaises(ValueError):
                    transport.request(arguments)
                capture.assert_not_called()

    def test_request_count_bound_precedes_network_io(self):
        for _index in range(transport.MAX_ATTEMPTS):
            transport.not_attempted('smtp-disabled', 'SMTP', '本次未执行')
        with mock.patch.object(transport, 'capture') as capture:
            with self.assertRaises(ValueError):
                transport.request(['https://ipinfo.check.place/' + EXAMPLE_IP + '?db=ipqualityscore'])
            capture.assert_not_called()

    def test_not_attempted_has_no_fabricated_request_measurements(self):
        transport.not_attempted('dnsbl-disabled', 'DNSBL', '未授权，本次未知')
        row = transport.load_receipts(self.receipts)[0]
        self.assertEqual(row['status'], 'not_attempted')
        self.assertEqual(row['error_kind'], 'not_attempted')
        self.assertEqual(row['target_ip'], EXAMPLE_IP)
        for name in ('url', 'attempted_at', 'elapsed_ms', 'http_status', 'curl_exit', 'response_bytes'):
            self.assertIsNone(row[name])

    def test_response_limit_and_failed_body_never_become_success(self):
        result, row, _capture = self.request(b'{"fraud_score":0,"country_code":"ZZ"}', category='response_limit')
        self.assertNotEqual(result, 0)
        self.assertEqual(row['error_kind'], 'response_limit')

    def test_partial_target_and_private_file_guards(self):
        transport.snapshot(io.BytesIO(json.dumps({'Head': {'IP': EXAMPLE_IP}, 'Mail': {'Port25': None}}).encode()))
        prior = (self.directory / 'partial.json').read_bytes()
        with self.assertRaises(ValueError):
            transport.snapshot(io.BytesIO(b'{"Head":{"IP":"192.0.2.2"}}'))
        self.assertEqual((self.directory / 'partial.json').read_bytes(), prior)
        (self.directory / 'partial.json').unlink()
        (self.directory / 'partial.json').symlink_to(self.directory / 'not-created')
        with self.assertRaises(OSError):
            transport.snapshot(io.BytesIO(prior))

    def test_discovery_distinct_fallback_preserves_failure(self):
        os.environ.pop('SINAN_IPQUALITY_TARGET_IP')
        responses = [self.captured(b'', status=0, code=6), self.captured(EXAMPLE_IP.encode())]
        with (mock.patch.object(transport, 'capture', side_effect=responses) as capture,
              mock.patch.object(sys, 'stdout', new=io.TextIOWrapper(io.BytesIO(), encoding='utf-8'))):
            self.assertEqual(transport.discover('4'), 0)
        rows = transport.load_receipts(self.receipts)
        self.assertEqual(capture.call_count, 2)
        self.assertEqual(rows[0]['error_kind'], 'dns')
        self.assertIsNone(rows[0]['target_ip'])
        self.assertEqual(rows[1]['target_ip'], EXAMPLE_IP)
        self.assertNotEqual(rows[0]['url'], rows[1]['url'])

    def test_zero_score_receipt_can_be_reclassified_when_page_contract_fails(self):
        self.request(b'{"fraud_score":0,"country_code":"ZZ"}')
        transport.annotate('IPQS', 'schema_mismatch', '后续字段不匹配')
        self.assertEqual(transport.source_state('IPQS'), 1)
        row = transport.load_receipts(self.receipts)[0]
        self.assertEqual(row['status'], 'failed')
        self.assertEqual(row['response_bytes'], len(b'{"fraud_score":0,"country_code":"ZZ"}'))


class PublicAddressTests(unittest.TestCase):
    def test_reserved_and_private_addresses_use_panel_rules(self):
        for value in ('192.0.2.1', '198.51.100.1', '203.0.113.1', '10.0.0.1', '100.64.0.1',
                      '169.254.1.1', '172.16.0.1', '127.0.0.1', '2001:db8::1', 'fc00::1', '::1'):
            with self.assertRaises(ValueError):
                transport.canonical_ip(value)


class RetainedPrefixTests(unittest.TestCase):
    def test_actual_pipe_guard_retains_at_most_budget_and_reaps_producer(self):
        command = [sys.executable, '-c', 'import os; os.write(1, b"x" * ' + str(transport.MAX_BODY + 8192) + ')']
        output, code, category = transport.capture(command, time.monotonic() + 10)
        self.assertEqual(category, 'response_limit')
        self.assertLessEqual(len(output), transport.MAX_BODY)
        self.assertEqual(output, b'x' * len(output))
        self.assertIsInstance(code, int)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source-cache', type=Path)
    options, remaining = parser.parse_known_args()
    SOURCE_CACHE = options.source_cache
    unittest.main(argv=[sys.argv[0], *remaining])
