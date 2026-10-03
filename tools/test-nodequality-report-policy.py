#!/usr/bin/env python3
"""Exercise actual packaging/serving with private sources and loopback reports."""
import json
import os
import sys

sys.dont_write_bytecode = True


def record(kind, args):
    value = {'kind': kind, 'argv': args, 'policy': os.environ.get('SINAN_UPLOAD_REPORT'),
             'nqenv': os.environ.get('NQENV')}
    data = (json.dumps(value, sort_keys=True) + '\n').encode()
    if len(data) > 8192:
        raise ValueError('fixture record exceeds byte limit')
    fd = os.open(os.environ['FIXTURE_TRACE'], os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


# Probe callbacks only append a bounded private record. Avoid reloading all
# packaging and source fixtures for every inert callback in a real chapter.
if __name__ == '__main__' and len(sys.argv) > 1 and sys.argv[1] == '--record':
    record(sys.argv[2], sys.argv[3:])
    raise SystemExit(0)


import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from pathlib import Path
import re
import signal
import shlex
import shutil
import subprocess
import tarfile
import threading
import tempfile
import unittest
from unittest import mock
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'plugins/nodequality'
READONLY_SOURCES = None


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


policy = module('report_policy', PLUGIN / 'report-policy.py')
source_tests = module('source_tests', ROOT / 'tools/test-nodequality-sources.py')
CONFIG = {
    'hardware.sh': ('check_Hardware', '\nadaptoslocale\n', 'get_virt get_os get_mb get_cpu test_cpu_sysbench test_cpu_gb5 get_gpu test_gpu get_mem test_mem get_disk test_disk get_mark', 'show_head show_os show_mb show_cpu show_gpu show_mem show_disk show_mark show_tail'),
    'ip.sh': ('check_IP', '\ngenerate_random_user_agent\n', 'db_maxmind db_ipinfo db_scamalytics db_ipregistry db_ipapi db_abuseipdb db_ip2location db_dbip db_ipdata db_ipqs MediaUnlockTest_TikTok MediaUnlockTest_DisneyPlus MediaUnlockTest_Netflix MediaUnlockTest_YouTube_Premium MediaUnlockTest_PrimeVideo_Region MediaUnlockTest_Reddit OpenAITest check_mail check_dnsbl', 'show_head show_basic show_basic_lite show_type show_type_lite show_score show_factor show_factor_lite show_media show_mail show_tail'),
    'net.sh': ('check_Net', '\ngenerate_random_user_agent\n', 'db_bgptools db_henet get_neighbor get_nat get_tcp get_delay get_route get_route_mode speedtest_test iperf_test', 'show_head show_bgp show_local show_conn show_delay show_route show_speedtest show_iperf show_tail'),
}
CONTROLLER = '''function run_HardwareQuality(){
    local params=""
    [[ "$run_hardware_quality_test" =~ ^[Ff]$ ]] && params=" -F"
    [[ "$run_hardware_quality_test" =~ ^[Vv]$ ]] && params=" -V"
    pre_fetch_info
    payload=$(declare -p osinfo meminfo diskinfo)
    curl -Ls https://Hardware.Check.Place | chroot_run "env NQENV=$(printf '%q' "$payload") bash -s -- $opt_lang $params -y -o /result/$hardware_quality_json_filename" # HQ预处理
}
function run_ip_quality(){
    chroot_run bash <(curl -Ls https://IP.Check.Place) $opt_ipv $opt_lang -y -o /result/$ip_quality_json_filename
}
function run_net_quality(){
    local params=""
    [[ "$run_net_quality_test" =~ ^[Ll]$ ]] && params=" -L"
    chroot_run bash <(curl -Ls https://Net.Check.Place) $opt_ipv $opt_lang $params -y -o /result/$net_quality_json_filename
}
function run_net_trace(){
    chroot_run bash <(curl -Ls https://Net.Check.Place) $opt_ipv $opt_lang -R -n -S 123 -o /result/$backroute_trace_json_filename
}
'''


def report_post(args):
    fields, destination, version = {}, None, None
    index = 0
    while index < len(args):
        value = args[index]
        if value in ('-4', '-6'):
            version = value[1:]
        elif value == '-s':
            pass
        elif value in ('-X', '-d', '--data-urlencode'):
            index += 1
            if value == '-X':
                if args[index] != 'POST':
                    raise ValueError('fixture requires POST')
            else:
                key, item = args[index].split('=', 1)
                if key not in ('type', 'json', 'content') or key in fields:
                    raise ValueError('unexpected fixture report fields')
                fields[key] = item
        elif value in ('http://upload.check.place', 'https://upload.check.place'):
            destination = value
        else:
            raise ValueError('fixture blocks unknown curl arguments')
        index += 1
    if destination is None or version not in ('4', '6') or set(fields) != {'type', 'json', 'content'}:
        raise ValueError('fixture requires the exact report call shape')
    endpoint = os.environ['FIXTURE_RECORDER']
    if not re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{0,4}/report', endpoint):
        raise ValueError('fixture only permits its own loopback recorder')
    request = urllib.request.Request(endpoint, data=urllib.parse.urlencode(fields).encode(), method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=2) as response:
        content = response.read(1025)
        if response.status != 200 or len(content) > 1024:
            raise ValueError('unexpected bounded fixture response')
    sys.stdout.write(content.decode())


class Recorder:
    def __init__(self):
        self.records = []
        self.errors = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    self.connection.settimeout(2)
                    length = int(self.headers.get('Content-Length', '0'))
                    if self.path != '/report' or not 0 < length <= 65536:
                        raise ValueError('invalid bounded report')
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise ValueError('truncated report')
                    fields = urllib.parse.parse_qs(body.decode(), strict_parsing=True)
                    if set(fields) != {'type', 'json', 'content'} or any(len(x) != 1 for x in fields.values()):
                        raise ValueError('invalid report fields')
                    owner.records.append({k: v[0] for k, v in fields.items()})
                    reply = ('https://Report.Check.Place/fixture-' + fields['type'][0]).encode()
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(reply)))
                    self.end_headers()
                    self.wfile.write(reply)
                except Exception as error:
                    owner.errors.append(type(error).__name__)
                    self.send_error(400)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:%d/report' % self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        if self.thread.is_alive() or self.errors:
            raise AssertionError('fixture recorder did not cleanly stop')


def canonical_body(name):
    if READONLY_SOURCES is None:
        entry = CONFIG[name][0]
        probes = ('test_cpu_sysbench\n[[ $mode_fast -eq 0 && $mode_privacy -eq 0 ]]&&test_cpu_gb5\n[[ $mode_fast -eq 0 && $mode_privacy -eq 0 ]]&&test_gpu\ntest_mem\ntest_disk\nget_mark\n' if name == 'hardware.sh' else '[[ $mode_route -eq 0 ]]&&get_route\n[[ $mode_route -eq 1 ]]&&get_route_mode\niperf_test\n' if name == 'net.sh' else 'MediaUnlockTest_Netflix\n[[ $mode_lite -eq 0 ]]&&db_scamalytics\n')
        data_name = {'hardware.sh': 'hwjson', 'ip.sh': 'ipjson', 'net.sh': 'netdata'}[name]
        save = policy.NET_OUTPUT.decode() if name == 'net.sh' else 'save_json\n'
        return entry + '(){\n' + probes + 'local report_link=""\n' * (name != 'net.sh') + save + policy.SOURCES[name]['original_guard'].decode() + '\nshow_head\n[[ -n $report_link ]]&&printf "%s\\n" "$report_link"\nprintf "%s\\n" "$' + data_name + '" > "$outputfile"\n}\n'
    source = source_tests.helper.ordinary(READONLY_SOURCES / name, policy.MAX_SOURCE)
    if hashlib.sha256(source).hexdigest() != policy.SOURCES[name]['source_sha256']:
        raise ValueError('readonly upstream orchestration SHA256 mismatch')
    entry, suffix, _, _ = CONFIG[name]
    prefix = entry + '(){\n'
    text = source.decode()
    if text.count(prefix) != 1:
        raise ValueError('readonly orchestration must be unique')
    body = prefix + text.split(prefix, 1)[1].split(suffix, 1)[0]
    if not body.endswith('}'):
        raise ValueError('readonly orchestration boundary mismatch')
    return body + '\n'


def controller():
    if READONLY_SOURCES is None:
        return CONTROLLER
    source = source_tests.helper.ordinary(READONLY_SOURCES / 'NodeQuality.sh', policy.MAX_SOURCE)
    if hashlib.sha256(source).hexdigest() != '4e1b25894cadf908ef61fb0d9ce874a75524c6dafc2ea26f0477107288e0c018':
        raise ValueError('readonly entrypoint SHA256 mismatch')
    text = source.decode()
    start, finish = text.index('function run_HardwareQuality(){\n'), text.index('\nuploadAPI=')
    return text[start:finish]


def script_recipe(name):
    entry, _, probes, shows = CONFIG[name]
    kind = name.removesuffix('.sh')
    tool = shlex.quote(str(Path(__file__).resolve()))
    python = shlex.quote(sys.executable)
    result = '#!/bin/bash\nscript_version="synthetic-fixture"\ncheck_bash(){\n:; }\ncheck_bash\n'
    result += 'fixture_record(){ ' + python + ' ' + tool + ' --record "$@"; }\n'
    result += source_tests.fixture.swap_anchors(name).decode()
    result += source_tests.fixture.dependency_anchors(name).decode()
    result += source_tests.fixture.data_anchors(name).decode()
    result += source_tests.fixture.ranking_anchors(name).decode()
    result += source_tests.fixture.ip_score_anchors(name).decode()
    result += source_tests.fixture.netflix_anchors(name).decode()
    # Identity/access policy anchors stay in uncalled synthetic helpers; the
    # real orchestration below still invokes only the recorded fixture probes.
    result += source_tests.fixture.browser_anchors(name).decode()
    result += source_tests.fixture.public_access_anchors(name).decode()
    result += 'fixture_record script ' + kind + ' "$@"\n'
    result += '''
mode_privacy=${FIXTURE_PRIVACY:-0}
mode_lite=${FIXTURE_LITE:-0}
mode_route=${FIXTURE_ROUTE:-0}
mode_fast=0
mode_skip=''
mode_json=0
mode_output=1
ADLines=0
IPV4work=1
IPV4check=1
Font_LineClear=''
Font_LineUp=''
Font_Suffix=''
stail[0]='Public report: '
bgp[0]=1
hw_report=fixture-hardware-report
ip_report=fixture-ip-report
net_report=fixture-net-report
version=${FIXTURE_VERSION:-4}
original_args=("$@")
while [[ $# -gt 0 ]]; do
  case "$1" in
    -4) version=4 ;;
    -6) version=6 ;;
    -F) mode_fast=1 ;;
    -V) : ;;
    -L) mode_skip+=6 ;;
    -R) mode_route=1; mode_skip+=467 ;;
    -S) shift; mode_skip+=$1 ;;
    -o) shift; outputfile=$1 ;;
    -E|-y|-n) : ;;
    *) printf '%s\\n' 'unexpected fixture script argument' >&2; exit 96 ;;
  esac
  shift
done
[[ $outputfile == /result/*.json && ${outputfile#/result/} != */* ]] || exit 95
outputfile="$FIXTURE_OUTPUT_DIRECTORY/${outputfile#/result/}"
record(){ fixture_record probe "$1"; }
hide_ipv4(){ record hide_ipv4; }
hide_ipv6(){ record hide_ipv6; }
countRunTimes(){ record countRunTimes; }
save_json(){ record save_json; hwjson=$FIXTURE_JSON; ipjson=$FIXTURE_JSON; netdata=$FIXTURE_JSON; }
'''
    for function in probes.split():
        result += function + '(){ record ' + function + '; }\n'
    for function in shows.split():
        result += function + '(){ record ' + function + '; printf "%s\\n" ' + shlex.quote('fixture-' + function) + '; }\n'
    result += 'curl(){ ' + python + ' ' + tool + ' --report-post "$@"; }\n'
    result += canonical_body(name)
    result += entry + ' ' + '192.0.2.1 "$version"\n'
    return result.encode()


def entry_recipe():
    python, tool = shlex.quote(sys.executable), shlex.quote(str(Path(__file__).resolve()))
    result = '#!/usr/bin/env bash\nset -e\n' + source_tests.fixture.swap_anchors('NodeQuality.sh').decode()
    result += source_tests.fixture.dependency_anchors('NodeQuality.sh').decode()
    result += 'chroot_run(){\n'
    # macOS Bash 3 closes process-substitution descriptors in bash -c. The
    # substitute opens them as stdin before exec, retaining the original argv
    # in the trace; the separate Linux fixture checks the real chroot boundary.
    result += '''if [[ ${BASH_VERSINFO[0]} -lt 4 && $# -ge 2 && $1 == bash && $2 == /dev/fd/* ]]; then
input=$(cat < "$2")
'''
    result += python + ' ' + tool + ' --record chroot "$@"\n'
    result += 'shift 2; printf "%s\\n" "$input" | bash -s -- "$@"\nelse\n'
    result += python + ' ' + tool + ' --record chroot "$@"\nbash -c "$*"\nfi; }\n'
    result += '''
pre_fetch_info(){ osinfo=(fixture-os); meminfo=(fixture-memory); diskinfo=(fixture-disk); }
opt_lang=-E
opt_ipv=-${FIXTURE_VERSION:-4}
run_hardware_quality_test=${FIXTURE_HARDWARE:-V}
run_net_quality_test=${FIXTURE_NETWORK:-L}
hardware_quality_json_filename=hardware_quality.json
ip_quality_json_filename=ip_quality.json
net_quality_json_filename=net_quality.json
backroute_trace_json_filename=backroute_trace.json
'''
    result += controller()
    result += '''
run_HardwareQuality > "$FIXTURE_OUTPUT_DIRECTORY/hardware_quality.log"
run_ip_quality > "$FIXTURE_OUTPUT_DIRECTORY/ip_quality.log"
run_net_quality > "$FIXTURE_OUTPUT_DIRECTORY/net_quality.log"
run_net_trace > "$FIXTURE_OUTPUT_DIRECTORY/backroute_trace.log"
'''
    # The collector receives only our synthetic ZIP; no entrypoint public upload.
    result += python + ' ' + tool + ' --assemble\n'
    result += 'python3 "$SINAN_REPORT_HELPER" capture "$SINAN_REPORT_WORKSPACE" < "$FIXTURE_OUTPUT_DIRECTORY/archive.base64"\n'
    result += '[[ $SINAN_UPLOAD_REPORT == true ]] || printf disabled > "$SINAN_REPORT_WORKSPACE/upload-disabled.txt"\nexit 0\n'
    return result.encode() + source_tests.fixture.loader_anchors('NodeQuality.sh', result.encode())


def assemble():
    import io
    import zipfile
    directory = Path(os.environ['FIXTURE_OUTPUT_DIRECTORY'])
    target = io.BytesIO()
    files = {'header_info.log': b'fixture-header\n'}
    for role in ('hardware_quality', 'ip_quality', 'net_quality', 'backroute_trace'):
        for extension in ('log', 'json'):
            data = (directory / (role + '.' + extension)).read_bytes()
            # Only the optional public link varies with the upload policy.
            if extension == 'log':
                data = re.sub(rb'[^\r\n]*https://Report\.Check\.Place/[^\r\n]*[\r\n]*', b'', data)
            files[role + '.' + extension] = data
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    (directory / 'archive.base64').write_bytes(base64.b64encode(target.getvalue()))


class PolicyTests(unittest.TestCase):
    def test_load_time_guard_rejects_invalid_values_before_bootstrap_or_probes(self):
        with tempfile.TemporaryDirectory(prefix='sinan-report-guard-') as temporary:
            marker = Path(temporary) / 'probe'
            program = policy.POLICY + b'printf started > "$FIXTURE_PROBE"\n'
            for value in (None, 'false', 'true', '', 'TRUE', '1', 'true\nfalse'):
                environment = {'PATH': os.environ['PATH'], 'FIXTURE_PROBE': str(marker)}
                if value is not None:
                    environment['SINAN_UPLOAD_REPORT'] = value
                run = subprocess.run(['bash'], input=program, env=environment,
                                     capture_output=True, timeout=3)
                allowed = value in (None, 'false', 'true')
                self.assertEqual(run.returncode == 0, allowed)
                self.assertEqual(marker.exists(), allowed)
                if marker.exists():
                    marker.unlink()

    def test_transform_requires_canonical_sha_known_role_unique_anchors_and_output_sha(self):
        with tempfile.TemporaryDirectory(prefix='sinan-report-transform-') as temporary:
            plugin = Path(temporary) / 'plugin'
            shutil.copytree(PLUGIN, plugin)
            contents = {name: source_tests.fixture.inert_source(name, policy)
                        for name in source_tests.helper.FILES}
            outputs = source_tests.fixture.prepare_policy(plugin, contents)
            private_policy = module('transform_fixture', plugin / 'report-policy.py')
            private_swap = module('swap_transform_fixture', plugin / 'swap-policy.py')
            for role in private_policy.SOURCES:
                expected = source_tests.fixture.undo_netflix(role, outputs[role])
                expected = source_tests.fixture.undo_ip_scores(role, expected)
                expected = source_tests.fixture.undo_ranking(role, expected)
                expected = source_tests.fixture.undo_data(role, expected, contents)
                expected = source_tests.fixture.undo_dependencies(role, expected, contents[role])
                if role == 'hardware.sh':
                    expected = private_swap.replace_once(expected, private_swap.MEMORY_GUARD, private_swap.HARDWARE_PREFIX)
                    expected = private_swap.replace_once(expected, private_swap.NO_SWAP_CLEANUP, private_swap.SWAP_CLEANUP)
                canonical = contents[role]
                self.assertEqual(private_policy.transform(role, canonical), expected)
                restored = expected.replace(policy.POLICY, b'', 1)
                restored = restored.replace(policy.SOURCES[role]['patched_guard'],
                                            policy.SOURCES[role]['original_guard'], 1)
                if role == 'net.sh':
                    restored = restored.replace(b'local report_link=""\n' + policy.NET_OUTPUT,
                                                policy.NET_OUTPUT, 1)
                self.assertEqual(restored, canonical)
                for changed in (canonical[:-1] + b'!', b'x' * (policy.MAX_SOURCE + 1)):
                    with self.assertRaises(ValueError):
                        private_policy.transform(role, changed)
                duplicate = canonical + b'check_bash(){\n'
                modified = dict(private_policy.SOURCES[role], source_sha256=hashlib.sha256(duplicate).hexdigest())
                with mock.patch.dict(private_policy.SOURCES, {role: modified}):
                    with self.assertRaisesRegex(ValueError, 'exactly once'):
                        private_policy.transform(role, duplicate)
                modified = dict(private_policy.SOURCES[role], patched_sha256='0' * 64)
                with mock.patch.dict(private_policy.SOURCES, {role: modified}):
                    with self.assertRaisesRegex(ValueError, 'patched.*SHA256'):
                        private_policy.transform(role, canonical)
            with self.assertRaisesRegex(ValueError, 'unknown'):
                private_policy.transform('unknown.sh', b'')

    def test_helper_missing_mutated_symlink_fifo_or_oversized_fails_without_stdout(self):
        fixture = source_tests.SourceTests(methodName='runTest')
        fixture.setUp()
        try:
            path = fixture.fixture_plugin / 'report-policy.py'
            original = path.read_bytes()
            for state in ('missing', 'mutated', 'symlink', 'fifo', 'oversized'):
                with self.subTest(state=state):
                    path.unlink()
                    if state == 'mutated':
                        path.write_bytes(original[:-1] + b'!')
                    elif state == 'symlink':
                        path.symlink_to(PLUGIN / 'report-policy.py')
                    elif state == 'fifo':
                        os.mkfifo(path, 0o600)
                    elif state == 'oversized':
                        path.write_bytes(b'x' * 65537)
                    run = fixture.shim('-Ls', 'https://Hardware.Check.Place')
                    self.assertNotEqual(run.returncode, 0)
                    self.assertEqual(run.stdout, b'')
                    self.assertFalse(fixture.called.exists())
                    self.assertFalse(fixture.executed.exists())
                    if path.exists() or path.is_symlink():
                        path.unlink()
                    path.write_bytes(original)
        finally:
            fixture.tearDown()

    def test_serving_rejects_wrong_transform_output_before_release(self):
        fixture = source_tests.SourceTests(methodName='runTest')
        fixture.setUp()
        try:
            for invalid in (b'wrong output', 'not bytes', b'x' * (policy.MAX_SOURCE + 2049)):
                with mock.patch.object(source_tests.helper, 'report_policy', return_value={
                        'transform': lambda *_: invalid, 'SOURCES': policy.SOURCES}):
                    with self.assertRaisesRegex(ValueError, 'output SHA256 or byte limit'):
                        source_tests.helper.serve(fixture.materialized, ['-Ls', 'https://Hardware.Check.Place'])
        finally:
            fixture.tearDown()


class WiringTests(unittest.TestCase):
    def setUp(self):
        self.base = source_tests.SourceTests(methodName='runTest')
        self.base.setUp()
        for row in self.base.lock['files']:
            if row['name'] in CONFIG:
                content = script_recipe(row['name'])
            elif row['name'] == 'NodeQuality.sh':
                content = entry_recipe()
            else:
                content = (self.base.sources / row['name']).read_bytes()
            (self.base.sources / row['name']).write_bytes(content)
            row['size'], row['sha256'] = len(content), hashlib.sha256(content).hexdigest()
        self.base.lock_path.write_text(json.dumps(self.base.lock))
        self.base.policy_outputs = source_tests.fixture.prepare_policy(self.base.fixture_plugin,
            {name: (self.base.sources / name).read_bytes() for name in source_tests.helper.FILES})
        self.tree, self.env = self.base.build_tree()
        self.plugin = self.tree / 'plugins/nodequality'
        # Only the private test copy relaxes host/root/Bash prerequisites.
        path = self.plugin / 'runner.sh.tmpl'
        text = path.read_text()
        self.assertEqual(text.count(source_tests.FULL_START_GUARD), 1)
        text = text.replace(source_tests.FULL_START_GUARD, ':')
        for guard in ("[[ $EUID == 0 ]] || die 'diagnostics require root'", "[[ ${BASH_VERSINFO[0]} -ge 4 ]] || die 'diagnostics require Bash >= 4'"):
            self.assertEqual(text.count(guard), 1)
            text = text.replace(guard, ':')
        path.write_text(text)
        self.recorder = Recorder()
        self.counter = 0

    def tearDown(self):
        try:
            self.recorder.close()
        finally:
            self.base.tearDown()

    def run_fixture(self, upload='false', old=False, **settings):
        self.counter += 1
        if old:
            path = self.plugin / 'source-helper.py'
            content = path.read_text()
            before = "REPORT_ROLES = frozenset({'hardware.sh', 'ip.sh', 'net.sh'})"
            self.assertEqual(content.count(before), 1)
            path.write_text(content.replace(before, 'REPORT_ROLES = frozenset()', 1))
        artifact_root = self.base.root / ('artifact-' + str(self.counter))
        run = subprocess.run(['bash', str(self.tree / 'tools/build-nodequality.sh'), 'amd64', str(artifact_root)], env=self.env, capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        artifact = artifact_root / 'nodequality' / source_tests.VERSION / 'amd64'
        runner = self.base.root / ('runner-' + str(self.counter))
        with tarfile.open(artifact, 'r:gz') as archive:
            runner.write_bytes(archive.extractfile('nodequality').read())
        workspace = self.base.root / ('workspace-' + str(self.counter))
        workspace.mkdir(mode=0o700)
        output = workspace / 'fixtures'
        output.mkdir(mode=0o700)
        trace = workspace / 'trace.jsonl'
        trace.write_text('')
        binaries = self.base.root / ('runtime-bin-' + str(self.counter))
        binaries.mkdir()
        for command in ('mount', 'umount', 'mountpoint', 'chroot'):
            path = binaries / command
            path.write_text('#!/bin/sh\nexit 0\n')
            path.chmod(0o700)
        path = binaries / 'uname'
        path.write_text("#!/bin/sh\nprintf 'Linux\\n'\n")
        path.chmod(0o700)
        env = {'PATH': str(binaries) + ':' + self.env['PATH'], 'LC_ALL': 'C', 'FIXTURE_TRACE': str(trace),
               'FIXTURE_OUTPUT_DIRECTORY': str(output), 'FIXTURE_RECORDER': self.recorder.url,
               'FIXTURE_JSON': '{"Head":{"Time":"2026-10-01T00:00:00Z"},"CPU":{"Score":4242},"GPU":{"Score":2424}}',
               'FIXTURE_VERSION': settings.get('version', '4'), 'FIXTURE_HARDWARE': settings.get('hardware', 'V'),
               'FIXTURE_NETWORK': settings.get('network', 'L'), 'FIXTURE_PRIVACY': settings.get('privacy', '0'),
               'FIXTURE_LITE': settings.get('lite', '0'), 'FIXTURE_ROUTE': settings.get('route', '0'),
               'report_link': 'https://Report.Check.Place/stale-fixture'}
        command = ['bash', str(runner), '--workspace', str(workspace), '--mode', 'full', '--ip-version', 'ipv' + env['FIXTURE_VERSION']]
        if upload is not None:
            command += ['--upload-report', upload]
        before = len(self.recorder.records)
        try:
            run = self.base.processes.run(command, env=env, timeout=20)
        finally:
            if old:
                (self.plugin / 'source-helper.py').write_text(content)
        if run.returncode and (workspace / 'log.txt').is_file():
            run.stderr += (workspace / 'log.txt').read_bytes()
        records = [json.loads(line) for line in trace.read_text().splitlines()]
        files = {p.name: p.read_bytes() for p in output.iterdir() if p.suffix in ('.json', '.log')}
        return run, records, files, self.recorder.records[before:], workspace

    def test_builder_runner_serve_and_four_original_callers_keep_outputs_and_argv(self):
        old = self.run_fixture('false', old=True)
        enabled = self.run_fixture('true')
        denied = self.run_fixture('false')
        default = self.run_fixture(None)
        for run, trace, files, _, workspace in (old, enabled, denied, default):
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertEqual(len([x for x in trace if x['kind'] == 'script']), 4)
            self.assertFalse((workspace / '.runner').exists())
            self.assertFalse((workspace / '.runner.lock').exists())
            self.assertTrue((workspace / 'report.zip').is_file())
            self.assertEqual({k: v for k, v in files.items() if k.endswith('.json')}, {k: v for k, v in old[2].items() if k.endswith('.json')})
        self.assertEqual(len(old[3]), 4)
        self.assertEqual(enabled[3], old[3])
        self.assertEqual(denied[3], [])
        self.assertEqual(default[3], [])
        for result in (denied, default):
            self.assertNotIn(b'stale-fixture', b''.join(result[2].values()))
            self.assertNotIn(b'https://Report.Check.Place/', b''.join(result[2].values()))
        expected = [[x['kind'], x['argv']] for x in old[1]]
        for result in (enabled, denied, default):
            self.assertEqual([[x['kind'], x['argv']] for x in result[1]], expected)
        scripts = [x for x in denied[1] if x['kind'] == 'script']
        self.assertEqual(scripts[0]['argv'], ['hardware', '-E', '-V', '-y', '-o', '/result/hardware_quality.json'])
        self.assertIn('fixture-os', scripts[0]['nqenv'])
        self.assertEqual(scripts[1]['argv'], ['ip', '-4', '-E', '-y', '-o', '/result/ip_quality.json'])
        self.assertEqual(scripts[2]['argv'], ['net', '-4', '-E', '-L', '-y', '-o', '/result/net_quality.json'])
        self.assertEqual(scripts[3]['argv'], ['net', '-4', '-E', '-R', '-n', '-S', '123', '-o', '/result/backroute_trace.json'])
        self.assertTrue(all(x['policy'] == 'false' for x in scripts))
        probes = [x['argv'][0] for x in denied[1] if x['kind'] == 'probe']
        self.assertIn('test_cpu_gb5', probes)
        self.assertIn('test_gpu', probes)

    def test_ipv6_fast_mode_and_existing_privacy_lite_route_conditions(self):
        for settings, count in (({'version': '6', 'hardware': 'F'}, 4), ({'privacy': '1'}, 0), ({'lite': '1'}, 3), ({'route': '1'}, 4)):
            run, trace, _, posts, _ = self.run_fixture('true', **settings)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertEqual(len(posts), count)
            scripts = [x for x in trace if x['kind'] == 'script']
            probes = [x['argv'][0] for x in trace if x['kind'] == 'probe']
            if settings.get('hardware') == 'F':
                self.assertIn('-F', scripts[0]['argv'])
                self.assertIn('-6', scripts[1]['argv'])
                self.assertNotIn('test_cpu_gb5', probes)
                self.assertNotIn('test_gpu', probes)
            if settings.get('privacy') == '1':
                self.assertNotIn('test_cpu_gb5', probes)
                self.assertNotIn('test_gpu', probes)
            if settings.get('lite') == '1':
                self.assertNotIn('db_scamalytics', probes)
            if settings.get('route') == '1':
                self.assertIn('get_route_mode', probes)
                self.assertNotIn('get_route', probes)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--report-post':
        report_post(sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == '--assemble':
        assemble()
    else:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('--readonly-upstream-dir', type=Path)
        options, remaining = parser.parse_known_args()
        READONLY_SOURCES = options.readonly_upstream_dir
        sys.argv = [sys.argv[0]] + remaining
        unittest.main()
