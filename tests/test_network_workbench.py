"""Isolated contracts and owned fixture processes; no real tools or host load."""
import importlib.util
import json
import os
import signal
import time
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('network_workbench', Path(__file__).resolve().parents[1] / 'tools/network-workbench.py')
WORKBENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKBENCH)


class NetworkWorkbenchContracts(unittest.TestCase):
    def setUp(self):
        WORKBENCH.MANIFEST = {}
        WORKBENCH.EXECUTION = {}
        WORKBENCH.CANCELLED = False
        WORKBENCH.FILE_FDS.clear()
        WORKBENCH.CREATED.clear()

    def tearDown(self):
        for descriptor in WORKBENCH.FILE_FDS:
            WORKBENCH.os.close(descriptor)
        WORKBENCH.FILE_FDS.clear()
        WORKBENCH.CREATED.clear()

    def execution(self, check):
        value = {'schema': 1, 'source_server': 1, 'source_label': 'fixture', 'role': 'source:1',
                 'check': check, 'budget': {'duration_secs': 60, 'memory_bytes': 64 * 1024 * 1024,
                                          'traffic_bytes': 256 * 1024 * 1024, 'rate_bps': 20_000_000},
                 'target': {'host': '192.0.2.1', 'authorization': 'fixture'}}
        WORKBENCH.EXECUTION = value
        return value

    def test_bounded_pipe_captures_a_fast_exiting_child_and_reaps_overflow(self):
        self.execution({'kind': 'cpu'})
        actual = subprocess.Popen
        owned = []
        def launch(*args, **kwargs):
            process = actual(*args, **kwargs)
            owned.append(process)
            return process
        try:
            with patch.object(WORKBENCH, 'resource_protection', return_value={}), \
                    patch.object(WORKBENCH.subprocess, 'Popen', side_effect=launch):
                code, output, _ = WORKBENCH.command([sys.executable, '-c', 'print("TEST_ONLY pipe")'], 3)
                self.assertEqual(code, 0)
                self.assertEqual(output, 'TEST_ONLY pipe\n')
                self.assertIsNone(WORKBENCH.PROCESS)
                with self.assertRaises(ValueError) as rejected:
                    WORKBENCH.command([sys.executable, '-c', 'import sys; sys.stdout.write("x" * 131072)'], 3)
                error = rejected.exception
                while error is not None and 'output exceeds' not in str(error):
                    error = error.__context__
                self.assertIsNotNone(error, 'original output-limit rejection must remain recorded')
                if WORKBENCH.PROCESS is not None:
                    self.assertIs(WORKBENCH.PROCESS, owned[-1])
                    self.assertRegex(str(rejected.exception), 'cleanup is unconfirmed')
        finally:
            # These two known fixture scripts never fork. Reap only their direct
            # Popen children; clearing this test module is isolation, not a
            # production process-group cleanup claim when group probing is denied.
            for process in owned:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
            if any(WORKBENCH.PROCESS is process for process in owned):
                WORKBENCH.PROCESS = None

    def test_exited_leader_with_live_pipe_descendant_still_reaps_the_owned_group(self):
        self.execution({'kind': 'cpu'})
        actual = subprocess.Popen
        launched = []
        def launch(*args, **kwargs):
            process = actual(*args, **kwargs)
            launched.append(process)
            return process
        code = ('import os,signal,time; pid=os.fork(); '
                'os._exit(0) if pid else None; '
                'signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(3.5)')
        with patch.object(WORKBENCH, 'resource_protection', return_value={}), \
                patch.object(WORKBENCH.subprocess, 'Popen', side_effect=launch):
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(ValueError, 'timeout|cleanup is unconfirmed'):
                    WORKBENCH.command([sys.executable, '-c', code], 0.3)
                self.assertLess(time.monotonic() - started, 5)
                self.assertEqual(launched[0].returncode, 0)
                if WORKBENCH.PROCESS is None:
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(launched[0].pid, 0)
                else:
                    self.assertIs(WORKBENCH.PROCESS, launched[0])
            finally:
                try:
                    os.killpg(launched[0].pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                WORKBENCH.PROCESS = None

    def test_group_cleanup_failure_retains_the_original_identity(self):
        process = Mock(pid=123456, stdout=None)
        WORKBENCH.PROCESS = process
        ticks = iter([0, 3, 0, 3])
        try:
            with patch.object(WORKBENCH.os, 'killpg'), \
                    patch.object(WORKBENCH.time, 'monotonic', side_effect=lambda: next(ticks)):
                with self.assertRaisesRegex(ValueError, 'cleanup is unconfirmed'):
                    WORKBENCH.reap_process_group()
            self.assertIs(WORKBENCH.PROCESS, process)
        finally:
            WORKBENCH.PROCESS = None

    def test_permission_denied_probe_is_rechecked_until_actual_group_disappears(self):
        process = Mock(pid=123456, stdout=None)
        WORKBENCH.PROCESS = process
        probes = []
        def observe(pid, sent):
            self.assertEqual(pid, process.pid)
            if sent == 0:
                probes.append(sent)
                if len(probes) == 2:
                    raise ProcessLookupError('TEST_ONLY group actually gone')
                raise PermissionError('TEST_ONLY group observation denied')
        try:
            with patch.object(WORKBENCH.os, 'killpg', side_effect=observe), \
                    patch.object(WORKBENCH.time, 'sleep'):
                WORKBENCH.reap_process_group()
            self.assertEqual(len(probes), 2)
            process.wait.assert_called_once_with(timeout=2)
            self.assertIsNone(WORKBENCH.PROCESS)
        finally:
            WORKBENCH.PROCESS = None

    def test_persistent_permission_denial_is_bounded_and_keeps_cleanup_identity(self):
        process = Mock(pid=123456, stdout=None)
        WORKBENCH.PROCESS = process
        ticks = iter([0, 0, 3, 0, 0, 3])
        try:
            with patch.object(WORKBENCH.os, 'killpg', side_effect=PermissionError('TEST_ONLY denied')) as observe, \
                    patch.object(WORKBENCH.time, 'monotonic', side_effect=lambda: next(ticks)), \
                    patch.object(WORKBENCH.time, 'sleep'):
                with self.assertRaisesRegex(ValueError, 'cleanup is unconfirmed'):
                    WORKBENCH.reap_process_group()
            self.assertEqual([call.args[1] for call in observe.call_args_list],
                             [signal.SIGTERM, 0, signal.SIGKILL, 0])
            process.wait.assert_not_called()
            self.assertIs(WORKBENCH.PROCESS, process)
        finally:
            WORKBENCH.PROCESS = None

    def test_cancel_signal_permission_denial_retains_identity_for_bounded_reaper(self):
        process = Mock(pid=123456, stdout=None)
        WORKBENCH.PROCESS = process
        try:
            with patch.object(WORKBENCH.os, 'killpg', side_effect=PermissionError('TEST_ONLY denied')):
                WORKBENCH.stop()
            self.assertTrue(WORKBENCH.CANCELLED)
            self.assertIs(WORKBENCH.PROCESS, process)
        finally:
            WORKBENCH.PROCESS = None

    def test_load_latency_refuses_missing_or_expired_exact_snapshot_before_dns(self):
        self.execution({'kind': 'throughput', 'latency_target': 'example.com', 'family': 'ipv4'})
        for frozen in (None, {'id': 'fixture', 'host': 'example.com', 'authorization': 'fixture',
                               'authorized_until': 1}):
            WORKBENCH.EXECUTION['latency_target'] = frozen
            with patch.object(WORKBENCH, 'addresses') as resolve:
                with self.assertRaisesRegex(ValueError, 'identity|expired'):
                    WORKBENCH.latency(WORKBENCH.EXECUTION['check'])
                resolve.assert_not_called()

    def test_resolution_and_total_deadline_recheck_frozen_authorization(self):
        self.execution({'kind': 'tcp', 'family': 'ipv4'})
        with patch.object(WORKBENCH.time, 'time', return_value=100):
            WORKBENCH.EXECUTION['target']['authorized_until'] = 110
            self.assertEqual(WORKBENCH.execution_seconds(WORKBENCH.EXECUTION), 10)
            WORKBENCH.EXECUTION['latency_target'] = {'authorized_until': 105}
            self.assertEqual(WORKBENCH.execution_seconds(WORKBENCH.EXECUTION), 5)
        def resolved(*args):
            WORKBENCH.EXECUTION['target']['authorized_until'] = 0
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('192.0.2.1', 443))]
        with patch.object(WORKBENCH.socket, 'getaddrinfo', side_effect=resolved):
            with self.assertRaisesRegex(ValueError, 'expired'):
                WORKBENCH.addresses('192.0.2.1', 443, WORKBENCH.EXECUTION['check'])

    def test_disk_scratch_over_report_limit_is_unlinked_before_truncate(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = str(Path(temporary).resolve())
            check = {'kind': 'disk', 'tool_version': '3.36', 'directory': directory,
                     'file_bytes': 2 * 1024 * 1024, 'block_bytes': 4096,
                     'queue_depth': 1, 'mode': 'write', 'read_percent': 0,
                     'duration_secs': 1}
            value = self.execution(check)
            value['budget']['disk_bytes'] = check['file_bytes']
            WORKBENCH.MANIFEST = {'allowed_test_directories': [directory]}
            self.assertEqual(WORKBENCH.file_size_limit(value), check['file_bytes'])
            original = os.ftruncate
            def truncate(descriptor, size):
                self.assertEqual(list(Path(directory).iterdir()), [])
                self.assertIn(descriptor, WORKBENCH.FILE_FDS)
                original(descriptor, size)
            free = Mock(f_bavail=4 * 1024 ** 3, f_frsize=1)
            with patch.object(WORKBENCH, 'supplied_tool', return_value='/fixture/fio'), \
                    patch.object(WORKBENCH.os, 'statvfs', return_value=free), \
                    patch.object(WORKBENCH.os, 'ftruncate', side_effect=truncate), \
                    patch.object(WORKBENCH, 'command', return_value=(0, '{}', [])):
                WORKBENCH.external(check)
            self.assertEqual(os.fstat(WORKBENCH.FILE_FDS[0]).st_size, check['file_bytes'])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_disk_truncate_failure_leaves_only_registered_unlinked_fd(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = str(Path(temporary).resolve())
            check = {'kind': 'disk', 'tool_version': '3.36', 'directory': directory,
                     'file_bytes': 1024 * 1024}
            self.execution(check)
            WORKBENCH.MANIFEST = {'allowed_test_directories': [directory]}
            free = Mock(f_bavail=4 * 1024 ** 3, f_frsize=1)
            with patch.object(WORKBENCH, 'supplied_tool', return_value='/fixture/fio'), \
                    patch.object(WORKBENCH.os, 'statvfs', return_value=free), \
                    patch.object(WORKBENCH.os, 'ftruncate', side_effect=OSError('fixture truncate')):
                with self.assertRaisesRegex(OSError, 'fixture truncate'):
                    WORKBENCH.external(check)
            self.assertEqual(len(WORKBENCH.FILE_FDS), 1)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_disk_scratch_limit_refuses_missing_or_excessive_budget(self):
        for size, budget in ((1024, 0), (2048, 1024), (9 * 1024 ** 3, 9 * 1024 ** 3),
                             (True, 1024)):
            with self.subTest(size=size, budget=budget):
                with self.assertRaisesRegex(ValueError, 'scratch size'):
                    WORKBENCH.file_size_limit({'check': {'kind': 'disk', 'file_bytes': size},
                                               'budget': {'disk_bytes': budget}})
        self.assertEqual(WORKBENCH.file_size_limit({'check': {'kind': 'tcp'}}),
                         WORKBENCH.LIMIT * 4)

    def test_stability_zero_cpu_workers_does_not_mean_all_processors(self):
        check = {'kind': 'stability', 'tool_version': '0.17.0', 'duration_secs': 10,
                 'cpu_workers': 0, 'memory_bytes': 16 * 1024 * 1024, 'io_workers': 0}
        self.execution(check)
        with patch.object(WORKBENCH, 'supplied_tool', return_value='/fixture/stress-ng'), \
                patch.object(WORKBENCH, 'command', return_value=(0, 'fixture metrics', [])) as run:
            WORKBENCH.external(check)
        args = run.call_args.args[0]
        self.assertNotIn('--cpu', args)
        self.assertNotIn('--cpu-load', args)
        self.assertIn('--vm', args)

    def test_bidirectional_report_keeps_two_explicit_flows_and_raw_intervals(self):
        check = {'kind': 'throughput', 'tool_version': '3.16', 'direction': 'bidirectional',
                 'receiver_server': 2, 'receiver_host': '192.0.2.2', 'port': 5201, 'family': 'ipv4',
                 'rate_bps': 1_000_000, 'duration_secs': 1, 'streams': 1, 'protocol': 'udp'}
        self.execution(check)
        output = {'intervals': [{'sum': {'sender': True, 'start': 0, 'end': 1,
                                       'bits_per_second': 1_000_000, 'bytes': 125000},
                                 'sum_bidir_reverse': {'sender': False, 'start': 0, 'end': 1,
                                                       'bits_per_second': 900_000, 'jitter_ms': 1.2,
                                                       'lost_packets': 1, 'packets': 100}}]}
        raw = json.dumps(output)
        with patch.object(WORKBENCH, 'supplied_tool', return_value='/fixture/iperf3'), \
                patch.object(WORKBENCH, 'command', return_value=(0, raw, [])) as run:
            data, original, success = WORKBENCH.external(check)
        self.assertTrue(success)
        self.assertEqual(original, raw)
        self.assertEqual(data['tool_output'], output)
        self.assertEqual(data['flows'], [{'sender': 'fixture', 'receiver': '服务器 2'},
                                         {'sender': '服务器 2', 'receiver': 'fixture'}])
        self.assertIsNone(data['sender'])
        self.assertIsNone(data['receiver'])
        self.assertIn('--bidir', run.call_args.args[0])
        self.assertIn('--udp', run.call_args.args[0])

    def test_cpu_hard_cap_and_weight_outside_independent_bounds_refuse_preflight(self):
        value = self.execution({'kind': 'cpu', 'tool_version': '1.0', 'threads': 1, 'duration_secs': 1})
        for hard_cap, weight in ((81, 20), (20, 101), (0, 20), (20, 0)):
            value['budget'].update(cpu_percent=hard_cap, cpu_weight=weight)
            with patch.object(WORKBENCH, 'supplied_tool') as tool, self.assertRaisesRegex(ValueError, 'CPU hard cap'):
                WORKBENCH.preflight(value)
            tool.assert_not_called()

    def test_dns_compression_cycles_are_bounded(self):
        with self.assertRaisesRegex(ValueError, 'recursion'):
            WORKBENCH.decode_name(b'\xc0\x00', 0)

    def test_dns_packets_cannot_read_past_length(self):
        for packet in (b'\x03ab', b'\xc0', b'\xff\xff'):
            with self.assertRaises(ValueError):
                WORKBENCH.decode_name(packet, 0)

    def test_offline_tool_requires_prior_license_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'iperf3'
            path.write_bytes(b'fixture')
            path.chmod(0o700)
            WORKBENCH.MANIFEST = {'tools': {'iperf3': {'path': str(path), 'licensed': False}}}
            with self.assertRaisesRegex(ValueError, 'license'):
                WORKBENCH.supplied_tool('iperf3', '3.16')
            WORKBENCH.MANIFEST['tools']['iperf3'].update(licensed=True, license='BSD', source_url='https://example.com/source', sha256='0' * 64, version='3.16')
            with self.assertRaisesRegex(ValueError, 'manifest'):
                WORKBENCH.supplied_tool('iperf3', '3.16')

    def test_expired_target_cannot_be_probed(self):
        WORKBENCH.EXECUTION = {'target': {'host': '192.0.2.1', 'authorization': 'fixture', 'authorized_until': 1}}
        with self.assertRaisesRegex(ValueError, 'expired'):
            WORKBENCH.target()

    def test_arbitrary_and_full_quality_checks_are_unregistered(self):
        for kind in ('node_quality_full', 'shell', 'download_and_execute'):
            with self.assertRaisesRegex(ValueError, 'unregistered'):
                WORKBENCH.preflight({'schema': 1, 'check': {'kind': kind}, 'budget': {'duration_secs': 1, 'memory_bytes': 16 * 1024 * 1024}})

    def test_bidirectional_multistream_budget_counts_both_senders(self):
        value = self.execution({'kind': 'throughput', 'tool_version': '3.16', 'direction': 'bidirectional',
                                'rate_bps': 20_000_000, 'duration_secs': 60, 'streams': 8, 'port': 5201})
        with patch.object(WORKBENCH, 'supplied_tool', return_value='/fixture/iperf3'), \
                patch.object(WORKBENCH, 'resource_protection') as protect, \
                self.assertRaisesRegex(ValueError, 'traffic budget'):
            WORKBENCH.preflight(value)
        protect.assert_not_called()

    def test_quic_without_http3_is_unavailable_before_protocol_execution(self):
        value = self.execution({'kind': 'quic', 'tool_version': '8.0.0', 'family': 'ipv4',
                                'url': 'https://192.0.2.1/', 'expected_status': 200})
        version = subprocess.CompletedProcess(['/fixture/curl', '--version'], 0, b'Features: HTTP2 SSL\n', b'')
        with patch.object(WORKBENCH, 'supplied_tool', return_value='/fixture/curl'), \
                patch.object(WORKBENCH.subprocess, 'run', return_value=version) as run, \
                patch.object(WORKBENCH, 'command') as command, \
                self.assertRaisesRegex(ValueError, 'without HTTP3'):
            WORKBENCH.preflight(value)
        run.assert_called_once_with(['/fixture/curl', '--version'], capture_output=True, timeout=2, check=True)
        command.assert_not_called()

    def test_speedtest_cannot_bypass_exact_traffic_budget_with_license(self):
        value = self.execution({'kind': 'speedtest', 'tool_version': '1.2.0', 'license_acknowledged': True})
        with patch.object(WORKBENCH, 'supplied_tool', return_value='/fixture/speedtest'), \
                patch.object(WORKBENCH, 'command') as command, \
                self.assertRaisesRegex(ValueError, 'exact traffic budget'):
            WORKBENCH.preflight(value)
        command.assert_not_called()

    def test_udp_silence_is_unknown_and_does_not_claim_closed_port(self):
        check = {'kind': 'udp', 'family': 'ipv4', 'protocol': 'echo', 'port': 12345,
                 'request_hex': '66697874757265', 'expected_hex': '66697874757265'}
        self.execution(check)
        sock = Mock()
        sock.recv.side_effect = socket.timeout()
        with patch.object(WORKBENCH, 'addresses', return_value=[('192.0.2.1', 12345)]), \
                patch.object(WORKBENCH.socket, 'socket') as constructor:
            constructor.return_value.__enter__.return_value = sock
            result, _, healthy = WORKBENCH.udp(check)
        self.assertFalse(healthy)
        self.assertEqual(result['outcome'], 'unknown')
        self.assertEqual(result['reason'], 'no_response_is_not_evidence_of_closed_port')

    def test_udp_dns_reply_requires_matching_transaction_and_response_bit(self):
        query = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) + WORKBENCH.dns_name('example.com') + struct.pack('!HH', 1, 1)
        reply = struct.pack('!HHHHHH', 0xff00, 0x8180, 1, 0, 0, 0) + query[12:]
        check = {'kind': 'udp', 'family': 'ipv4', 'protocol': 'dns', 'port': 53,
                 'request_hex': query.hex(), 'expected_hex': reply[:1].hex()}
        self.execution(check)
        sock = Mock()
        sock.recv.return_value = reply
        with patch.object(WORKBENCH, 'addresses', return_value=[('192.0.2.1', 53)]), \
                patch.object(WORKBENCH.socket, 'socket') as constructor:
            constructor.return_value.__enter__.return_value = sock
            result, _, healthy = WORKBENCH.udp(check)
        self.assertFalse(healthy)
        self.assertEqual(result['outcome'], 'unexpected_response')

    def test_unknown_route_hops_do_not_invent_ip_asn_or_reverse_path(self):
        WORKBENCH.EXECUTION = {'role': 'source:1'}
        value = WORKBENCH.path_report(' 1 192.0.2.1 1.0 ms\n 2 * * *\n', 'traceroute')
        self.assertEqual(value['hops'][0]['ip'], '192.0.2.1')
        self.assertIsNone(value['hops'][1]['ip'])
        self.assertIsNone(value['hops'][1]['asn'])
        self.assertIsNone(value['external_as_path'])
        self.assertTrue(value['unanswered_hops_are_not_path_loss'])

    def test_disk_outside_allowlist_rejects_before_creating_test_file(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = str(Path(directory).resolve())
            check = {'kind': 'disk', 'tool_version': '3.38', 'directory': directory}
            self.execution(check)
            with patch.object(WORKBENCH, 'supplied_tool', return_value='/fixture/fio'), \
                    patch.object(WORKBENCH.tempfile, 'mkstemp') as create, \
                    self.assertRaisesRegex(ValueError, 'allowlist'):
                WORKBENCH.external(check)
            create.assert_not_called()

    def test_disk_uses_small_anonymous_owned_file_and_keeps_fio_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = str(Path(directory).resolve())
            check = {'kind': 'disk', 'tool_version': '3.38', 'directory': directory, 'file_bytes': 4096,
                     'block_bytes': 512, 'queue_depth': 2, 'mode': 'randrw', 'read_percent': 75, 'duration_secs': 1}
            self.execution(check)
            WORKBENCH.MANIFEST = {'allowed_test_directories': [directory]}
            free = Mock(f_bavail=10_000_000, f_frsize=4096)
            def inert_fio(args, maximum):
                descriptor = int(next(arg.split('/proc/self/fd/')[1] for arg in args if arg.startswith('--filename=')))
                self.assertEqual(WORKBENCH.os.fstat(descriptor).st_size, 4096)
                self.assertEqual(WORKBENCH.os.fstat(descriptor).st_nlink, 0)
                self.assertEqual(list(Path(directory).iterdir()), [])
                self.assertIn('--iodepth=2', args)
                self.assertIn('--rw=randrw', args)
                self.assertIn('--rwmixread=75', args)
                return 0, json.dumps({'jobs': [{'read': {'iops': 1}}]}), []
            with patch.object(WORKBENCH, 'supplied_tool', return_value='/fixture/fio'), \
                    patch.object(WORKBENCH.os, 'statvfs', return_value=free), \
                    patch.object(WORKBENCH, 'command', side_effect=inert_fio) as command:
                data, _, healthy = WORKBENCH.external(check)
            self.assertTrue(healthy)
            self.assertEqual(data['tool_output']['jobs'][0]['read']['iops'], 1)
            self.assertEqual(command.call_count, 1)
            self.assertTrue(all(not filename.exists() for filename in WORKBENCH.CREATED))


if __name__ == '__main__':
    unittest.main()
