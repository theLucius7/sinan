#!/usr/bin/env python3
"""Prepare authenticated Debian inputs and export an offline diagnostic rootfs.

This tool never downloads inputs, purchases licenses or enables full diagnostics.
Use an independently approved native Debian builder image. All commands require
explicit inputs; no example lock, image or tool digest is silently trusted.
"""
import argparse
import contextlib
import datetime
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

MAX_LOCK = 8 * 1024 * 1024
MAX_METADATA = 1024 * 1024
MAX_INDEX = 256 * 1024 * 1024
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_SOURCE = 1024 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_STREAM = MAX_EXPANDED + 64 * 1024 * 1024
MAX_MEMBERS = 100000
PREPARE_SECONDS = 600
BUILD_SECONDS = 3600
EXPORT_SECONDS = 600
CHILD_CLEANUP_SECONDS = 5
SHA256 = re.compile(r'[0-9a-f]{64}')
NAME = re.compile(r'[a-z0-9][a-z0-9+.-]*')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+:~_-]*')
ARCHES = {'amd64', 'arm64'}
SIGNERS = {
    'debian': {'B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8',
               '4D64FEC119C2029067D6E791F8D2585B8783D481'},
    'debian-security': {'05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0'},
}
TOOL_PATHS = {'gpgv': '/usr/bin/gpgv', 'mmdebstrap': '/usr/bin/mmdebstrap',
              'unshare': '/usr/bin/unshare'}
# This is the requested open-source base, not a replacement for missing tools.
TOOL_PACKAGES = {
    'bash': 'bash', 'base64': 'coreutils', 'head': 'coreutils',
    'wc': 'coreutils', 'date': 'coreutils', 'timeout': 'coreutils',
    'numfmt': 'coreutils', 'grep': 'grep', 'sed': 'sed', 'awk': 'gawk',
    'find': 'findutils', 'tar': 'tar', 'gzip': 'gzip', 'xz': 'xz-utils',
    'zip': 'zip', 'curl': 'curl', 'wget': 'wget', 'jq': 'jq', 'bc': 'bc',
    'openssl': 'openssl', 'dmidecode': 'dmidecode', 'sensors': 'lm-sensors',
    'lspci': 'pciutils', 'lscpu': 'util-linux', 'smartctl': 'smartmontools',
    'fio': 'fio', 'sysbench': 'sysbench', 'nc': 'netcat-openbsd',
    'dig': 'bind9-dnsutils', 'convert': 'imagemagick', 'mtr': 'mtr-tiny',
    'iperf3': 'iperf3', 'stun': 'stun-client', 'free': 'procps',
    'update-ca-certificates': 'ca-certificates', 'clinfo': 'clinfo',
}
PENDING = [
    'nexttrace: fixed GPL source, Go toolchain and module closure not prepared',
    'geekbench5: appropriate license and offline no-upload execution not approved',
    'speedtest: Ookla provenance, redistribution, terms and upload behavior not approved',
    'curl-impersonate: browser impersonation conflicts with native-identity policy',
    'nvidia-smi: optional device driver and its license are not supplied by the base',
]
META_DIR = 'usr/share/sinan-rootfs'
PROVENANCE_KIND = 'sinan-nodequality-debian12-preparation'
# Independent profiles may require a fresh admission and public inventory proof.
# The default preserves the original NodeQuality API and every receipt schema.
INPUT_PROFILE = None
CAPACITY_KIND = 'sinan-nodequality-factory-capacity'
DEFAULT_MAX_OUTPUT = 4 * 1024 * 1024 * 1024
DEFAULT_RESERVE_FREE = 512 * 1024 * 1024
DEFAULT_RESERVE_INODES = 1024
MAX_FACTORY_OUTPUT = 16 * 1024 * 1024 * 1024
CAPACITY_POLL_SECONDS = 0.25


@contextlib.contextmanager
def deferred_signals():
    """Defer interrupts until a newly owned resource has a cleanup handle."""
    require(hasattr(signal, 'pthread_sigmask'), 'safe resource ownership requires POSIX signal masks')
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
    original = None
    try:
        yield
    except BaseException as error:
        original = error
        raise
    finally:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        except BaseException:
            if original is None:
                raise


@contextlib.contextmanager
def cli_signals():
    def interrupted(number, _frame):
        raise SystemExit(128 + number)
    previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGHUP)}
    original = None
    try:
        for number in previous:
            signal.signal(number, interrupted)
        yield
    except BaseException as error:
        original = error
        raise
    finally:
        failure = None
        for number, handler in previous.items():
            try:
                signal.signal(number, handler)
            except BaseException as error:
                failure = failure or error
        if original is None and failure is not None:
            raise failure


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')


def digest(content):
    return hashlib.sha256(content).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def decode(content):
    return json.loads(content, object_pairs_hook=unique_object)


class Deadline:
    def __init__(self, seconds, capacity=None):
        self.end = time.monotonic() + seconds
        self.capacity = capacity

    def check(self):
        require(time.monotonic() < self.end, 'overall operation deadline exceeded')
        if self.capacity is not None:
            self.capacity.check()

    def remaining(self):
        self.check()
        return self.end - time.monotonic()


def relative(value):
    require(isinstance(value, str) and value and '\\' not in value
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+~/-]*', value), 'unsafe relative input path')
    require(all(part not in ('', '.', '..') for part in value.split('/')), 'input path traversal')
    return value


def main_pool_path(archive, value):
    require(archive in SIGNERS, 'unsupported Debian archive')
    prefix = 'pool/updates/main/' if archive == 'debian-security' else 'pool/main/'
    require(relative(value).startswith(prefix), 'package/source path differs from its Debian main archive')
    return value


def private_directory(path):
    path = Path(path).absolute()
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and not path.is_symlink()
            and metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022,
            'expected an owned ordinary directory not writable by another account')
    return path.resolve(strict=True)


def open_regular(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(descriptor, 'rb')
    metadata = os.fstat(stream.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
        stream.close()
        raise ValueError('expected a bounded ordinary file')
    return stream, metadata


def input_path(root, value):
    root = private_directory(root)
    value = relative(value)
    path = root
    for component in value.split('/')[:-1]:
        path /= component
        require(stat.S_ISDIR(path.lstat().st_mode) and not path.is_symlink(), 'input parent is not ordinary')
    return path / value.split('/')[-1]


def read_regular(path, limit, deadline=None):
    stream, _ = open_regular(path, limit)
    with stream:
        result = bytearray()
        while True:
            if deadline:
                deadline.check()
            chunk = stream.read(min(65536, limit - len(result) + 1))
            if not chunk:
                break
            result.extend(chunk)
            require(len(result) <= limit, 'ordinary file exceeds its byte limit')
    return bytes(result)


def file_identity(path, limit, deadline=None):
    stream, metadata = open_regular(path, limit)
    length, value = 0, hashlib.sha256()
    with stream:
        while True:
            if deadline:
                deadline.check()
            chunk = stream.read(min(65536, limit - length + 1))
            if not chunk:
                break
            length += len(chunk)
            require(length <= limit, 'ordinary file exceeds its byte limit')
            value.update(chunk)
    require(length == metadata.st_size, 'ordinary file changed while reading')
    return {'sha256': value.hexdigest(), 'size': length}


def descriptor(value, limit):
    require(isinstance(value, dict) and set(value) == {'blob', 'sha256', 'size'}, 'invalid input descriptor')
    relative(value['blob'])
    require(isinstance(value['sha256'], str) and SHA256.fullmatch(value['sha256']), 'invalid input digest')
    require(type(value['size']) is int and 0 < value['size'] <= limit, 'invalid input size')
    return value


def checked_blob(cache, value, limit, deadline):
    descriptor(value, limit)
    path = input_path(cache, value['blob'])
    require(file_identity(path, limit, deadline) == {'sha256': value['sha256'], 'size': value['size']},
            'locked input checksum or size mismatch')
    return path


def control_records(content):
    require(b'\0' not in content, 'binary control index')
    record, previous = {}, None
    for line in content.decode('utf-8').splitlines():
        if not line:
            if record:
                yield record
            record, previous = {}, None
        elif line[0] in ' \t':
            require(previous is not None, 'orphan control continuation')
            record[previous] += '\n' + line[1:]
        else:
            require(':' in line, 'invalid control field')
            key, value = line.split(':', 1)
            require(key and key not in record, 'duplicate control field')
            record[key] = value.lstrip()
            previous = key
    if record:
        yield record


def checksum_rows(value):
    result = {}
    for line in value.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'\s*([0-9a-f]{64})\s+([0-9]+)\s+(\S+)\s*', line)
        require(match is not None, 'invalid SHA256 index row')
        path = relative(match[3])
        require(path not in result, 'duplicate SHA256 index path')
        result[path] = {'sha256': match[1], 'size': int(match[2])}
    require(result, 'missing SHA256 index rows')
    return result


def expanded_index(path, limit, deadline):
    raw, _ = open_regular(path, MAX_INDEX)
    with raw:
        if str(path).endswith('.xz'):
            stream = lzma.LZMAFile(raw)
        elif str(path).endswith('.gz'):
            stream = gzip.GzipFile(fileobj=raw)
        else:
            raise ValueError('only fixed gzip/xz Debian indices are supported')
        with stream:
            content = bytearray()
            while True:
                deadline.check()
                chunk = stream.read(min(65536, limit - len(content) + 1))
                if not chunk:
                    break
                content.extend(chunk)
                require(len(content) <= limit, 'expanded Debian index exceeds its limit')
    return bytes(content)


def index_records(path, limit, deadline):
    """Read authenticated compressed indices one bounded paragraph at a time."""
    require(type(limit) is int and 0 < limit <= MAX_INDEX, 'invalid expanded index limit')
    raw, _ = open_regular(path, MAX_INDEX)
    with raw:
        if str(path).endswith('.xz'):
            stream = lzma.LZMAFile(raw)
        elif str(path).endswith('.gz'):
            stream = gzip.GzipFile(fileobj=raw)
        else:
            raise ValueError('only fixed gzip/xz Debian indices are supported')
        with stream:
            total, paragraph, pending = 0, bytearray(), b''
            while True:
                deadline.check()
                chunk = stream.read(min(65536, limit - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                require(total <= limit, 'expanded Debian index exceeds its limit')
                lines = (pending + chunk).split(b'\n')
                pending = lines.pop()
                for line in lines:
                    deadline.check()
                    if line.endswith(b'\r'):
                        line = line[:-1]
                    if line:
                        paragraph.extend(line + b'\n')
                    elif paragraph:
                        yield from control_records(bytes(paragraph))
                        paragraph.clear()
                    require(len(paragraph) <= MAX_LOCK, 'Debian control record exceeds its limit')
                require(len(paragraph) + len(pending) <= MAX_LOCK, 'Debian control record exceeds its limit')
            if pending:
                paragraph.extend(pending)
            if paragraph:
                yield from control_records(bytes(paragraph))


def validate_lock(lock):
    require(isinstance(lock, dict) and set(lock) == {'schema', 'arch', 'source_epoch', 'builder',
            'keyring', 'repositories', 'packages', 'sources'}, 'invalid rootfs input lock fields')
    require(type(lock['schema']) is int and lock['schema'] == 1 and lock['arch'] in ARCHES, 'unsupported lock identity')
    builder = lock['builder']
    require(isinstance(builder, dict) and set(builder) == {'image_sha256', 'arch', 'tools'}, 'invalid builder identity')
    require(builder['arch'] == lock['arch'] and SHA256.fullmatch(builder['image_sha256'] or ''), 'fixed native builder image required')
    require(isinstance(builder['tools'], list) and len(builder['tools']) == len(TOOL_PATHS), 'complete build tool identities required')
    seen_tools = set()
    for tool in builder['tools']:
        require(isinstance(tool, dict) and set(tool) == {'name', 'path', 'version', 'sha256', 'size'}, 'invalid build tool identity')
        require(tool['name'] in TOOL_PATHS and tool['name'] not in seen_tools
                and tool['path'] == TOOL_PATHS[tool['name']], 'unknown/duplicate build tool path')
        require(isinstance(tool['version'], str) and 0 < len(tool['version']) <= 128, 'fixed build tool version required')
        descriptor({'blob': tool['name'], 'sha256': tool['sha256'], 'size': tool['size']}, MAX_ARCHIVE)
        seen_tools.add(tool['name'])
    return validate_materials({key: value for key, value in lock.items() if key != 'builder'})


def validate_materials(materials):
    """Validate collected source inputs without inventing a builder identity."""
    require(isinstance(materials, dict) and set(materials) == {'schema', 'arch', 'source_epoch',
            'keyring', 'repositories', 'packages', 'sources'}, 'invalid source material fields')
    require(type(materials['schema']) is int and materials['schema'] == 1
            and materials['arch'] in ARCHES, 'unsupported material identity')
    lock = materials
    require(type(lock['source_epoch']) is int and 0 < lock['source_epoch'] < 2**32, 'fixed source epoch required')
    descriptor(lock['keyring'], MAX_LOCK)
    require(isinstance(lock['repositories'], list) and 2 <= len(lock['repositories']) <= 3, 'main and security snapshots required')
    repos, timestamps = {}, {}
    for repo in lock['repositories']:
        require(isinstance(repo, dict) and set(repo) == {'id', 'archive', 'timestamp', 'suite', 'inrelease', 'indices'}, 'invalid snapshot repository')
        relative(repo['id'])
        require('/' not in repo['id'] and repo['id'] not in repos, 'duplicate repository identity')
        require(repo['archive'] in SIGNERS and re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', repo['timestamp'] or ''), 'fixed actual snapshot timestamp required')
        datetime.datetime.strptime(repo['timestamp'], '%Y%m%dT%H%M%SZ')
        allowed_suites = {'bookworm', 'bookworm-updates'} if repo['archive'] == 'debian' else {'bookworm-security'}
        require(repo['suite'] in allowed_suites, 'repository is not Debian 12 main/security')
        require(repo['archive'] not in timestamps or timestamps[repo['archive']] == repo['timestamp'], 'one archive must use one snapshot timestamp')
        timestamps[repo['archive']] = repo['timestamp']
        descriptor(repo['inrelease'], MAX_LOCK)
        require(isinstance(repo['indices'], list) and len(repo['indices']) == 2, 'binary and source indices required')
        kinds = set()
        for index in repo['indices']:
            require(isinstance(index, dict) and set(index) == {'kind', 'path', 'blob', 'sha256', 'size'}, 'invalid Debian index identity')
            require(index['kind'] in ('Packages', 'Sources') and index['kind'] not in kinds, 'duplicate Debian index kind')
            expected = 'main/binary-' + lock['arch'] + '/Packages' if index['kind'] == 'Packages' else 'main/source/Sources'
            require(index['path'] in (expected + '.xz', expected + '.gz'), 'index differs from its fixed architecture/role')
            descriptor({key: index[key] for key in ('blob', 'sha256', 'size')}, MAX_INDEX)
            kinds.add(index['kind'])
        repos[repo['id']] = repo
    require(set(timestamps) == set(SIGNERS) and any(repo['suite'] == 'bookworm' for repo in repos.values()), 'main/security snapshot pair is incomplete')
    require(isinstance(lock['packages'], list) and 0 < len(lock['packages']) <= 2048, 'complete fixed package closure required')
    seen = set()
    for row in lock['packages']:
        require(isinstance(row, dict) and set(row) == {'repository', 'name', 'version', 'architecture',
                'filename', 'blob', 'sha256', 'size', 'source_name', 'source_version'}, 'invalid binary package lock')
        require(row['repository'] in repos and NAME.fullmatch(row['name'] or '') and VERSION.fullmatch(row['version'] or ''), 'invalid package identity')
        require(row['architecture'] in (lock['arch'], 'all') and row['name'] not in seen, 'duplicate/foreign binary package')
        require(NAME.fullmatch(row['source_name'] or '') and VERSION.fullmatch(row['source_version'] or ''), 'fixed corresponding source identity required')
        main_pool_path(repos[row['repository']]['archive'], row['filename'])
        descriptor({key: row[key] for key in ('blob', 'sha256', 'size')}, MAX_ARCHIVE)
        seen.add(row['name'])
    require(set(TOOL_PACKAGES.values()) <= seen, 'open-source tool/base package inventory is incomplete')
    require(isinstance(lock['sources'], list) and 0 < len(lock['sources']) <= 2048, 'corresponding source inventory required')
    source_pairs = set()
    for row in lock['sources']:
        require(isinstance(row, dict) and set(row) == {'repository', 'name', 'version', 'directory', 'files'}, 'invalid corresponding source lock')
        pair = (row['name'], row['version'])
        require(row['repository'] in repos and NAME.fullmatch(row['name'] or '') and VERSION.fullmatch(row['version'] or '')
                and pair not in source_pairs, 'duplicate/invalid corresponding source identity')
        main_pool_path(repos[row['repository']]['archive'], row['directory'])
        require(isinstance(row['files'], list) and 0 < len(row['files']) <= 64, 'complete source file inventory required')
        names = set()
        for value in row['files']:
            require(isinstance(value, dict) and set(value) == {'name', 'blob', 'sha256', 'size'}, 'invalid corresponding source file')
            require('/' not in relative(value['name']) and value['name'] not in names, 'duplicate source file')
            descriptor({key: value[key] for key in ('blob', 'sha256', 'size')}, MAX_SOURCE)
            names.add(value['name'])
        require(any(name.endswith('.dsc') for name in names), 'corresponding .dsc is missing')
        source_pairs.add(pair)
    require(source_pairs == {(row['source_name'], row['source_version']) for row in lock['packages']}, 'binary/source closure mismatch')
    return repos


def verify_tools(lock, approved_image, required, deadline=None):
    require(isinstance(approved_image, str) and SHA256.fullmatch(approved_image), 'independently approved builder digest required')
    require(lock['builder']['image_sha256'] == approved_image, 'builder image was not independently approved')
    for tool in lock['builder']['tools']:
        if tool['name'] in required:
            require(file_identity(tool['path'], MAX_ARCHIVE, deadline) == {'sha256': tool['sha256'], 'size': tool['size']}, 'build tool bytes differ from the approved lock')


def run_bounded(arguments, deadline, output_limit, stderr=subprocess.STDOUT, extra_env=None, capacity=None):
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC'}
    if extra_env:
        require(set(extra_env) == {'SOURCE_DATE_EPOCH', 'DEBIAN_FRONTEND'}
                and extra_env['SOURCE_DATE_EPOCH'].isdigit()
                and extra_env['DEBIAN_FRONTEND'] == 'noninteractive', 'unsupported build environment')
        environment.update(extra_env)
    require(hasattr(os, 'waitid') and hasattr(os, 'WNOWAIT'), 'bounded child collection requires waitid/WNOWAIT')
    process, selector = None, None
    output = bytearray()
    capacity = capacity or deadline.capacity
    try:
        if capacity is not None:
            capacity.check(force=True)
        with deferred_signals():
            process = subprocess.Popen(arguments, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=stderr, start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            for key, _ in selector.select(min(0.1, deadline.remaining())):
                chunk = os.read(key.fileobj.fileno(), min(65536, output_limit - len(output) + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                require(len(output) <= output_limit, 'trusted command output exceeds its limit')
            deadline.check()
            if capacity is not None:
                capacity.check()
        # Observe completion without reaping the session leader. Its PID then
        # cannot be reused before this function removes remaining group members.
        while True:
            if capacity is not None:
                capacity.check()
            result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if result is not None:
                require(result.si_code == os.CLD_EXITED and result.si_status == 0,
                        'trusted build/verification command failed')
                break
            time.sleep(min(0.01, deadline.remaining()))
        return bytes(output)
    except BaseException as error:
        # Preserve original types (including cancellation and disk failure).
        # Logs remain bounded and are evidence, never executable instructions.
        error.factory_command = {'argv': list(arguments), 'output': bytes(output[:output_limit]),
                                 'output_truncated': len(output) > output_limit,
                                 'returncode': None}
        if process is not None:
            try:
                result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if result is not None:
                    error.factory_command['returncode'] = (result.si_status if result.si_code == os.CLD_EXITED
                                                           else -result.si_status)
            except OSError:
                pass
        raise
    finally:
        original = sys.exc_info()[1]
        failure = None
        actions = []
        if selector is not None:
            actions.append(selector.close)
        if process is not None:
            actions.extend((process.stdout.close, lambda: os.killpg(process.pid, signal.SIGKILL),
                            lambda: process.wait(timeout=CHILD_CLEANUP_SECONDS)))
        previous_mask = None
        try:
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
        except BaseException as error:
            failure = error
        for action in actions:
            try:
                action()
            except ProcessLookupError:
                # The owned process group can already be empty.
                pass
            except BaseException as error:
                failure = failure or error
        if original is not None and hasattr(original, 'factory_command') and process is not None:
            original.factory_command['cleanup_returncode'] = process.returncode
        if previous_mask is not None:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except BaseException as error:
                failure = failure or error
        if failure is not None:
            if original is None:
                raise failure
            if hasattr(original, 'add_note'):
                original.add_note('Child cleanup also failed: ' + type(failure).__name__)


def valid_signers(status, archive, timestamp):
    permitted, found = SIGNERS[archive], set()
    latest = int(datetime.datetime.strptime(timestamp, '%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc).timestamp())
    for line in status.decode('ascii').splitlines():
        require(line.startswith('[GNUPG:] '), 'unexpected signature verifier status')
        values = line[len('[GNUPG:] '):].split()
        require(values and values[0] not in {'BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'KEYREVOKED'}, 'bad/expired/revoked signature status')
        if values[0] == 'VALIDSIG':
            require(len(values) in (10, 11) and values[8] in ('8', '9', '10', '11'), 'unsupported signature digest/status')
            require(values[3].isdigit() and int(values[3]) <= latest, 'signature postdates fixed snapshot')
            primary = values[10] if len(values) == 11 else values[1]
            if primary in permitted:
                found.add(primary)
    require(found, 'no approved Debian 12 primary signer')
    return sorted(found)


def source_pair(row):
    source = row.get('Source', row['Package'])
    match = re.fullmatch(r'([a-z0-9][a-z0-9+.-]*)(?: \(([^()]+)\))?', source)
    require(match is not None, 'invalid binary Source field')
    return match[1], match[2] or row['Version']


def repository_url(repo, path):
    relative(path)
    return 'https://snapshot.debian.org/archive/' + repo['archive'] + '/' + repo['timestamp'] + '/' + path


def all_descriptors(lock):
    result = [(lock['keyring'], MAX_LOCK)]
    for repo in lock['repositories']:
        result.append((repo['inrelease'], MAX_LOCK))
        result.extend(({key: index[key] for key in ('blob', 'sha256', 'size')}, MAX_INDEX) for index in repo['indices'])
    result.extend(({key: row[key] for key in ('blob', 'sha256', 'size')}, MAX_ARCHIVE) for row in lock['packages'])
    result.extend(({key: file[key] for key in ('blob', 'sha256', 'size')}, MAX_SOURCE) for row in lock['sources'] for file in row['files'])
    seen = {}
    for value, limit in result:
        require(value['blob'] not in seen or seen[value['blob']] == value, 'one input blob has conflicting identities')
        seen[value['blob']] = value
    return result


def capacity_plan(operation, materials, parent, max_output_bytes=DEFAULT_MAX_OUTPUT,
                  reserve_free_bytes=DEFAULT_RESERVE_FREE,
                  reserve_free_inodes=DEFAULT_RESERVE_INODES):
    """Conservative admission, not input authentication or builder approval."""
    validate_materials({key: value for key, value in materials.items() if key != 'builder'})
    require(operation in ('prepare', 'build', 'export'), 'unknown factory operation')
    require(type(max_output_bytes) is int and MAX_LOCK <= max_output_bytes <= MAX_FACTORY_OUTPUT,
            'invalid factory output budget')
    require(type(reserve_free_bytes) is int and DEFAULT_RESERVE_FREE <= reserve_free_bytes <= MAX_FACTORY_OUTPUT,
            'invalid factory free-disk reserve')
    require(type(reserve_free_inodes) is int and DEFAULT_RESERVE_INODES <= reserve_free_inodes <= MAX_MEMBERS,
            'invalid factory free-inode reserve')
    parent = private_directory(parent)
    disk = os.statvfs(parent)
    block = disk.f_frsize
    require(type(block) is int and 0 < block <= MAX_METADATA, 'unsupported factory block size')
    require(disk.f_bavail >= 0 and disk.f_favail >= 0, 'invalid factory capacity observation')

    def rounded(size):
        return ((size + block - 1) // block) * block

    files, directories = {}, {''}

    def account(name, size):
        relative(name)
        require(name not in files or files[name] == size, 'conflicting preparation destination')
        files[name] = size
        directory = PurePosixPath(name).parent
        while str(directory) != '.':
            directories.add(directory.as_posix())
            directory = directory.parent

    descriptors = all_descriptors(materials)
    if operation == 'prepare':
        for value, _limit in descriptors:
            account('input-cache/' + value['blob'], value['size'])
        for repo in materials['repositories']:
            prefix = 'mirrors/' + repo['id'] + '/'
            account(prefix + 'bookworm-archive-keyring.gpg', materials['keyring']['size'])
            account(prefix + 'dists/' + repo['suite'] + '/InRelease', repo['inrelease']['size'])
            for index in repo['indices']:
                account(prefix + 'dists/' + repo['suite'] + '/' + index['path'], index['size'])
            for package in materials['packages']:
                if package['repository'] == repo['id']:
                    account(prefix + package['filename'], package['size'])
        payload = sum(files.values())
        allocated = sum(rounded(size) for size in files.values()) + len(directories) * block
        members = len(files) + len(directories)
        # Lock, inventory, receipts, two bounded Release scratch files and logs.
        scratch = 8 * MAX_LOCK + 4 * MAX_METADATA
        scratch_members = 32
    elif operation == 'build':
        payload = MAX_EXPANDED
        members = MAX_MEMBERS
        # Every member may consume a block tail, including directories/links.
        allocated = payload + members * block
        scratch = (sum(rounded(row['size']) for row in materials['packages'])
                   + sum(MAX_INDEX for repo in materials['repositories']
                         for row in repo['indices'] if row['kind'] == 'Packages')
                   + 8 * MAX_LOCK + 4 * MAX_METADATA)
        scratch_members = len(materials['packages']) + 128
    else:
        payload = MAX_ARCHIVE + MAX_LOCK + 4 * MAX_METADATA
        members = 16
        allocated = payload + members * block
        scratch = 4 * MAX_LOCK + 4 * MAX_METADATA
        scratch_members = 32
    required_bytes = allocated + rounded(scratch)
    required_inodes = members + scratch_members
    free_bytes = disk.f_bavail * block
    free_inodes = disk.f_favail
    reasons = []
    if required_bytes > max_output_bytes:
        reasons.append('output_budget')
    if free_bytes < required_bytes + reserve_free_bytes:
        reasons.append('free_disk_reserve')
    if free_inodes < required_inodes + reserve_free_inodes:
        reasons.append('free_inode_reserve')
    return {'schema': 1, 'kind': CAPACITY_KIND + '-plan', 'operation': operation,
            'arch': materials['arch'], 'output_parent': str(parent),
            'device': parent.stat().st_dev, 'block_size': block,
            'input_descriptors_sha256': digest(canonical([value for value, _ in descriptors])),
            'materials_sha256': digest(canonical(materials)),
            'destinations_sha256': digest(canonical({'files': files, 'directories': sorted(directories)})),
            'payload_bytes': payload, 'payload_allocated_bytes': allocated,
            'scratch_bytes': rounded(scratch), 'required_bytes': required_bytes,
            'required_inodes': required_inodes, 'max_output_bytes': max_output_bytes,
            'reserve_free_bytes': reserve_free_bytes, 'reserve_free_inodes': reserve_free_inodes,
            'observed_free_bytes': free_bytes, 'observed_free_inodes': free_inodes,
            'admitted': not reasons, 'reasons': reasons,
            'source_authenticated': False, 'builder_approved': False,
            'reproducibility_verified': False, 'full_ready': False}


class FactoryCapacity:
    """Bounded polling protection; no filesystem quota or exclusive reservation."""
    def __init__(self, output, plan, deadline):
        require(plan['admitted'] is True, 'factory capacity plan rejected: ' + ','.join(plan['reasons']))
        self.output = private_directory(output)
        self.parent = private_directory(self.output.parent)
        require(str(self.parent) == plan['output_parent'] and self.parent.stat().st_dev == plan['device'],
                'factory output parent differs from admission')
        self.plan, self.deadline = plan, deadline
        self.parent_identity = self.identity(self.parent)
        self.output_identity = self.identity(self.output)
        require(self.output_identity[0] == plan['device'], 'factory output crosses a filesystem')
        self.next_check = 0
        self.last = None
        self.peak_bytes = self.peak_inodes = 0
        self.check(force=True)

    @staticmethod
    def identity(path):
        metadata = path.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and not path.is_symlink(), 'factory directory identity changed')
        return metadata.st_dev, metadata.st_ino

    def check(self, force=False, additional_bytes=0, additional_inodes=0):
        require(type(additional_bytes) is int and additional_bytes >= 0
                and type(additional_inodes) is int and additional_inodes >= 0, 'invalid prospective capacity')
        now = time.monotonic()
        if not force and additional_bytes == 0 and additional_inodes == 0 and now < self.next_check:
            return self.last
        require(now < self.deadline.end, 'overall operation deadline exceeded')
        require(self.identity(self.parent) == self.parent_identity
                and self.identity(self.output) == self.output_identity, 'factory directory identity changed')
        if sys.platform == 'linux':
            ensure_no_mounts(self.output)
        size, members, stack = 0, 0, [(self.output, self.output_identity)]
        while stack:
            require(time.monotonic() < self.deadline.end, 'overall operation deadline exceeded')
            folder, expected = stack.pop()
            try:
                descriptor_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            except FileNotFoundError:
                require(folder != self.output, 'factory output disappeared')
                continue
            try:
                metadata = os.fstat(descriptor_fd)
                require(stat.S_ISDIR(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == expected,
                        'factory output contains a foreign filesystem or changed directory')
                size += max(metadata.st_size, metadata.st_blocks * 512)
                members += 1
                with os.scandir(descriptor_fd) as children:
                    for child in children:
                        require(time.monotonic() < self.deadline.end, 'overall operation deadline exceeded')
                        try:
                            metadata = child.stat(follow_symlinks=False)
                        except FileNotFoundError:
                            # A controlled builder can remove its own temporary file.
                            continue
                        require(metadata.st_dev == self.plan['device'], 'factory output contains a foreign filesystem')
                        if stat.S_ISDIR(metadata.st_mode):
                            stack.append((folder / child.name, (metadata.st_dev, metadata.st_ino)))
                        else:
                            size += max(metadata.st_size, metadata.st_blocks * 512)
                            members += 1
                        require(size + additional_bytes <= self.plan['max_output_bytes'], 'factory output budget exceeded')
                        require(members + len(stack) <= max(MAX_MEMBERS, self.plan['required_inodes']) + 4096,
                                'factory output member scan exceeds limit')
            finally:
                os.close(descriptor_fd)
        require(self.identity(self.parent) == self.parent_identity
                and self.identity(self.output) == self.output_identity, 'factory directory identity changed')
        disk = os.statvfs(self.output)
        require(disk.f_frsize == self.plan['block_size'] and disk.f_bavail >= 0 and disk.f_favail >= 0,
                'factory filesystem observation changed')
        self.peak_bytes = max(self.peak_bytes, size)
        self.peak_inodes = max(self.peak_inodes, members)
        free_bytes, free_inodes = disk.f_bavail * disk.f_frsize, disk.f_favail
        self.last = {'output_bytes': size, 'output_inodes': members,
                     'free_bytes': free_bytes, 'free_inodes': free_inodes,
                     'peak_output_bytes': self.peak_bytes, 'peak_output_inodes': self.peak_inodes}
        require(size + additional_bytes <= self.plan['max_output_bytes'], 'factory output budget exceeded')
        require(free_bytes >= self.plan['reserve_free_bytes'] + additional_bytes, 'factory free-disk reserve crossed')
        require(free_inodes >= self.plan['reserve_free_inodes'] + additional_inodes, 'factory free-inode reserve crossed')
        self.next_check = time.monotonic() + CAPACITY_POLL_SECONDS
        return self.last

    def write(self, path, content, mode=0o644):
        require(len(content) <= MAX_LOCK, 'factory control file exceeds its reader limit')
        path = Path(path).absolute()
        require(path.parent == self.output and relative(path.name) == path.name,
                'factory control write must remain in the owned output')
        self.check(force=True, additional_bytes=len(content) + self.plan['block_size'], additional_inodes=1)
        descriptor_fd = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor_fd)
            require((metadata.st_dev, metadata.st_ino) == self.output_identity, 'factory directory identity changed')
            with os.fdopen(os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                   mode, dir_fd=descriptor_fd), 'wb') as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor_fd)
        self.check(force=True)

    def finish(self):
        observation = self.check(force=True)
        self.write(self.output / 'factory-capacity.json', canonical({
            'schema': 1, 'kind': CAPACITY_KIND + '-observation', 'plan_sha256': digest(canonical(self.plan) + b'\n'),
            'observation': observation, 'poll_seconds': CAPACITY_POLL_SECONDS,
            'hard_quota': False, 'source_authenticated': False,
            'builder_approved': False, 'full_ready': False}) + b'\n')


def admit_factory(operation, materials, requested_output, max_output_bytes,
                  reserve_free_bytes, reserve_free_inodes):
    plan = capacity_plan(operation, materials, Path(requested_output).absolute().parent,
                         max_output_bytes, reserve_free_bytes, reserve_free_inodes)
    require(plan['admitted'], 'factory capacity plan rejected: ' + ','.join(plan['reasons'])
            + '; required_bytes=' + str(plan['required_bytes']) + '; free_bytes=' + str(plan['observed_free_bytes']))
    return plan


def verify_inputs(lock, cache, approved_image, deadline):
    validate_lock(lock)
    verify_tools(lock, approved_image, {'gpgv'}, deadline)
    return verify_authenticated_sources({key: value for key, value in lock.items() if key != 'builder'}, cache, deadline)


def verify_authenticated_sources(materials, cache, deadline):
    """Authenticate Debian source bytes; this API never approves a builder."""
    repos = validate_materials(materials)
    lock = materials
    for value, limit in all_descriptors(lock):
        checked_blob(cache, value, limit, deadline)
    keyring = input_path(cache, lock['keyring']['blob'])
    binaries, sources, signatures = {}, {}, []
    wanted_binaries = {(item['repository'], item['name'], item['version'], item['architecture'])
                       for item in lock['packages']}
    wanted_sources = {(item['repository'], item['name'], item['version']) for item in lock['sources']}
    scratch_parent = deadline.capacity.output if deadline.capacity is not None else None
    with tempfile.TemporaryDirectory(prefix='sinan-rootfs-signatures-', dir=scratch_parent) as name:
        scratch = Path(name)
        for repo in lock['repositories']:
            deadline.check()
            output = scratch / (repo['id'] + '.Release')
            status = run_bounded(['/usr/bin/gpgv', '--homedir', str(scratch), '--keyring', str(keyring),
                                  '--status-fd', '1', '--output', str(output),
                                  str(input_path(cache, repo['inrelease']['blob']))],
                                 Deadline(min(30, deadline.remaining()), capacity=deadline.capacity), 65536, stderr=subprocess.DEVNULL)
            signers = valid_signers(status, repo['archive'], repo['timestamp'])
            rows = list(control_records(read_regular(output, MAX_LOCK, deadline)))
            require(len(rows) == 1 and rows[0].get('Origin') == 'Debian'
                    and rows[0].get('Codename') == repo['suite'], 'signed Release has wrong origin/codename')
            sums = checksum_rows(rows[0].get('SHA256', ''))
            signatures.append({'repository': repo['id'], 'primary_fingerprints': signers,
                               'inrelease_sha256': repo['inrelease']['sha256']})
            for index in repo['indices']:
                require(sums.get(index['path']) == {key: index[key] for key in ('sha256', 'size')}, 'index is not covered by signed Release')
                for row in index_records(input_path(cache, index['blob']), MAX_INDEX, deadline):
                    deadline.check()
                    if index['kind'] == 'Packages':
                        key = (repo['id'], row.get('Package'), row.get('Version'), row.get('Architecture'))
                        if key in wanted_binaries:
                            require(key not in binaries, 'ambiguous signed binary index')
                            binaries[key] = row
                    else:
                        key = (repo['id'], row.get('Package'), row.get('Version'))
                        if key in wanted_sources:
                            require(key not in sources, 'ambiguous signed source index')
                            sources[key] = row
    for item in lock['packages']:
        key = (item['repository'], item['name'], item['version'], item['architecture'])
        row = binaries.get(key)
        require(row is not None and row.get('Filename') == item['filename']
                and row.get('SHA256') == item['sha256'] and row.get('Size') == str(item['size']), 'binary is not covered by signed Packages')
        require(source_pair(row) == (item['source_name'], item['source_version']), 'binary corresponding source differs from lock')
    for item in lock['sources']:
        row = sources.get((item['repository'], item['name'], item['version']))
        require(row is not None and row.get('Directory') == item['directory'], 'source is not covered by signed Sources')
        require(checksum_rows(row.get('Checksums-Sha256', '')) ==
                {value['name']: {key: value[key] for key in ('sha256', 'size')} for value in item['files']},
                'corresponding source file inventory is incomplete or altered')
    return material_inventory(materials), signatures


def material_inventory(materials):
    """Derive the public source inventory from the exact fixed material closure."""
    repos = validate_materials(materials)
    lock = materials
    return {'schema': 1, 'arch': lock['arch'], 'packages': lock['packages'],
                 'sources': [{'name': row['name'], 'version': row['version'], 'repository': row['repository'],
                              'directory': row['directory'], 'files': [dict(name=value['name'], sha256=value['sha256'], size=value['size'],
                                  url=repository_url(repos[row['repository']], row['directory'] + '/' + value['name'])) for value in row['files']]}
                             for row in lock['sources']],
                 'tools': [{'command': command, 'package': package, 'architectures': sorted(ARCHES)}
                           for command, package in sorted(TOOL_PACKAGES.items())], 'pending_capabilities': PENDING}


def write_new(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as output:
        os.fchmod(output.fileno(), mode)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def reserve_output(path):
    path = Path(path).absolute()
    parent = private_directory(path.parent)
    require(not parent.stat().st_mode & 0o022, 'output parent is writable by another account')
    require(path.name not in ('', '.', '..'), 'invalid new output name')
    path = parent / path.name
    path.mkdir(mode=0o700)
    return path


def ensure_no_mounts(path):
    require(sys.platform == 'linux', 'mount-safe cleanup requires Linux mount inventory')
    path = private_directory(path)
    mountinfo = read_regular('/proc/self/mountinfo', MAX_LOCK).decode('utf-8')
    for line in mountinfo.splitlines():
        fields = line.split()
        require(len(fields) >= 6, 'invalid builder mount inventory')
        mount = re.sub(r'\\([0-7]{3})', lambda value: chr(int(value[1], 8)), fields[4])
        require(mount != str(path) and not mount.startswith(str(path) + '/'),
                'cleanup blocked by remaining mount; owned output retained')


def cleanup_output(output, guard_mounts=False, capacity=None, expected_identity=None):
    original = sys.exc_info()[1]
    removed = False
    try:
        with deferred_signals():
            output = private_directory(output)
            if expected_identity is not None:
                require(FactoryCapacity.identity(output) == expected_identity[0]
                        and FactoryCapacity.identity(output.parent) == expected_identity[1],
                        'cleanup blocked by replaced owned directory')
            if INPUT_PROFILE is not None:
                INPUT_PROFILE.ensure_cleanup_safe(output)
            if capacity is not None:
                require(capacity.identity(output) == capacity.output_identity
                        and capacity.identity(output.parent) == capacity.parent_identity,
                        'cleanup blocked by replaced owned directory')
            if guard_mounts:
                ensure_no_mounts(output)
            shutil.rmtree(output)
            removed = True
    except BaseException as error:
        if original is None:
            raise
        if removed:
            # A deferred second signal arrived after successful deletion;
            # retain the original interruption without claiming leftover data.
            return True
        if hasattr(original, 'add_note'):
            original.add_note('Owned output cleanup failed; retained at ' + str(output))
        try:
            print('Cleanup failed; owned output retained: ' + str(output) + ' (' + type(error).__name__ + ')', file=sys.stderr)
        except BaseException:
            pass
    return removed


def preserve_factory_failure(output, operation, error, capacity):
    """Best-effort independent, new evidence; never overwrite an earlier run."""
    evidence = None
    try:
        parent = private_directory(output.parent)
        if capacity is not None:
            require(FactoryCapacity.identity(parent) == capacity.parent_identity,
                    'failure evidence parent identity changed')
        command = getattr(error, 'factory_command', None)
        raw_output = command['output'] if command is not None else b''
        require(len(raw_output) <= MAX_LOCK, 'failure command evidence exceeds limit')
        receipt = {'schema': 1, 'kind': CAPACITY_KIND + '-failure', 'operation': operation,
                   'output_directory': str(output), 'error_type': type(error).__name__,
                   'error': str(error)[:1024], 'command': None,
                   'capacity': capacity.last if capacity is not None else None,
                   'cleanup': 'pending', 'full_ready': False}
        if command is not None:
            receipt['command'] = {key: value for key, value in command.items() if key != 'output'}
            receipt['command']['output'] = {'path': 'command.log', **{'size': len(raw_output), 'sha256': digest(raw_output)}}
        reserve_bytes = capacity.plan['reserve_free_bytes'] if capacity is not None else DEFAULT_RESERVE_FREE
        reserve_inodes = capacity.plan['reserve_free_inodes'] if capacity is not None else DEFAULT_RESERVE_INODES
        receipt['reserve_free_bytes'], receipt['reserve_free_inodes'] = reserve_bytes, reserve_inodes
        raw_receipt = canonical(receipt) + b'\n'
        require(len(raw_receipt) <= MAX_METADATA, 'failure receipt exceeds limit')
        disk = os.statvfs(parent)
        require(disk.f_bavail * disk.f_frsize >= reserve_bytes + len(raw_output) + len(raw_receipt) + 4 * disk.f_frsize
                and disk.f_favail >= reserve_inodes + 4, 'insufficient reserved capacity for bounded failure evidence')
        with deferred_signals():
            evidence = Path(tempfile.mkdtemp(prefix=output.name + '-failure-', dir=parent))
        write_new(evidence / 'failure.json', raw_receipt, 0o600)
        if command is not None:
            write_new(evidence / 'command.log', raw_output, 0o600)
        print('Factory failure evidence retained: ' + str(evidence), file=sys.stderr)
        return evidence, receipt, FactoryCapacity.identity(evidence)
    except BaseException as recording_error:
        if hasattr(error, 'add_note'):
            error.add_note('Factory failure evidence could not be completed: ' + type(recording_error).__name__)
        if evidence is not None:
            try:
                print('Partial factory failure evidence retained: ' + str(evidence), file=sys.stderr)
            except BaseException:
                pass
        return None


def record_factory_cleanup(evidence, removed, error):
    if evidence is None:
        return
    directory, receipt, identity = evidence
    try:
        require(FactoryCapacity.identity(directory) == identity, 'failure evidence directory changed')
        disk = os.statvfs(directory)
        require(disk.f_bavail * disk.f_frsize >= receipt['reserve_free_bytes'] + 2 * disk.f_frsize
                and disk.f_favail >= receipt['reserve_free_inodes'] + 1, 'insufficient reserved capacity for cleanup evidence')
        write_new(directory / 'cleanup.json', canonical({'schema': 1,
            'output_directory': receipt['output_directory'], 'removed': removed,
            'retained': not removed}) + b'\n', 0o600)
    except BaseException as recording_error:
        if error is not None and hasattr(error, 'add_note'):
            error.add_note('Cleanup evidence could not be completed: ' + type(recording_error).__name__)


def copy_locked(cache, value, target, limit, deadline):
    source = checked_blob(cache, value, limit, deadline)
    input_stream, metadata = open_regular(source, limit)
    length, sha256 = 0, hashlib.sha256()
    with input_stream:
        require(metadata.st_size == value['size'], 'locked input changed before copying')
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb', buffering=0) as output:
            os.fchmod(output.fileno(), 0o644)
            while True:
                deadline.check()
                chunk = input_stream.read(min(65536, value['size'] - length + 1))
                if not chunk:
                    break
                length += len(chunk)
                require(length <= value['size'] and length <= limit, 'copied locked input exceeds byte limit')
                if deadline.capacity is not None:
                    deadline.capacity.check(additional_bytes=len(chunk) + deadline.capacity.plan['block_size'])
                require(output.write(chunk) == len(chunk), 'short locked input write')
                sha256.update(chunk)
        require(length == value['size'] and sha256.hexdigest() == value['sha256'],
                'locked input changed while copying')
    require(file_identity(target, limit, deadline) == {key: value[key] for key in ('sha256', 'size')}, 'copied locked input changed')


def prepare(lock_path, cache, output, approved_image, max_output_bytes=DEFAULT_MAX_OUTPUT,
            reserve_free_bytes=DEFAULT_RESERVE_FREE, reserve_free_inodes=DEFAULT_RESERVE_INODES):
    deadline = Deadline(PREPARE_SECONDS)
    lock_bytes = read_regular(lock_path, MAX_LOCK, deadline)
    lock = decode(lock_bytes)
    validate_lock(lock)
    if INPUT_PROFILE is not None:
        INPUT_PROFILE.require_prepare_context(output, deadline)
        require(lock_bytes == canonical(lock) + b'\n', 'profile input lock must retain its canonical binding bytes')
    verify_tools(lock, approved_image, {'gpgv'}, deadline)
    plan = admit_factory('prepare', lock, output, max_output_bytes, reserve_free_bytes, reserve_free_inodes)
    requested_output, output = output, None
    capacity = None
    owned_identity, evidence = None, None
    complete = False
    try:
        with deferred_signals():
            output = reserve_output(requested_output)
            owned_identity = FactoryCapacity.identity(output), FactoryCapacity.identity(output.parent)
            capacity = FactoryCapacity(output, plan, deadline)
        deadline.capacity = capacity
        capacity.write(output / 'capacity-plan.json', canonical(plan) + b'\n')
        inventory, signatures = verify_inputs(lock, cache, approved_image, deadline)
        profile = INPUT_PROFILE.prepare(lock, cache, output, deadline) if INPUT_PROFILE is not None else None
        if INPUT_PROFILE is not None:
            capacity = deadline.capacity
        capacity.write(output / 'inputs-lock.json', lock_bytes)
        for value, limit in all_descriptors(lock):
            target = output / 'input-cache' / value['blob']
            if not target.exists():
                copy_locked(cache, value, target, limit, deadline)
        for repo in lock['repositories']:
            mirror = output / 'mirrors' / repo['id']
            # The supplied file-mirror hook exposes this entire ordinary mirror
            # at the same absolute path inside the build chroot. Signed-By must
            # reference a keyring in that mounted mirror, not a host-only cache.
            copy_locked(cache, lock['keyring'], mirror / 'bookworm-archive-keyring.gpg', MAX_LOCK, deadline)
            copy_locked(cache, repo['inrelease'], mirror / 'dists' / repo['suite'] / 'InRelease', MAX_LOCK, deadline)
            for index in repo['indices']:
                copy_locked(cache, {key: index[key] for key in ('blob', 'sha256', 'size')},
                            mirror / 'dists' / repo['suite'] / index['path'], MAX_INDEX, deadline)
            for row in lock['packages']:
                if row['repository'] == repo['id']:
                    copy_locked(cache, {key: row[key] for key in ('blob', 'sha256', 'size')}, mirror / row['filename'], MAX_ARCHIVE, deadline)
        capacity.write(output / 'source-inventory.json', canonical(inventory) + b'\n')
        receipt = {'schema': 1, 'arch': lock['arch'], 'inputs_lock_sha256': digest(lock_bytes),
                   'source_inventory_sha256': file_identity(output / 'source-inventory.json', MAX_LOCK, deadline)['sha256'],
                   'approved_builder_image_sha256': approved_image, 'signatures': signatures,
                   'full_ready': False, 'reproducibility_verified': False}
        if profile is not None:
            receipt['profile_proof_sha256'] = profile['sha256']
        capacity.write(output / 'prepared.json', canonical(receipt) + b'\n')
        capacity.finish()
        complete = True
        return receipt
    except BaseException as error:
        if output is not None:
            evidence = preserve_factory_failure(output, 'prepare', error, deadline.capacity if INPUT_PROFILE is not None else capacity)
        raise
    finally:
        if not complete and output is not None:
            removed = cleanup_output(output, guard_mounts=sys.platform == 'linux', capacity=capacity,
                                     expected_identity=owned_identity)
            if evidence is None and removed and sys.exc_info()[1] is not None:
                evidence = preserve_factory_failure(output, 'prepare', sys.exc_info()[1], deadline.capacity if INPUT_PROFILE is not None else capacity)
            record_factory_cleanup(evidence, removed, sys.exc_info()[1])


def verify_mirrors(directory, lock, deadline):
    expected = {}
    for repo in lock['repositories']:
        prefix = 'mirrors/' + repo['id'] + '/'
        expected[prefix + 'bookworm-archive-keyring.gpg'] = (lock['keyring'], MAX_LOCK)
        expected[prefix + 'dists/' + repo['suite'] + '/InRelease'] = (repo['inrelease'], MAX_LOCK)
        for index in repo['indices']:
            expected[prefix + 'dists/' + repo['suite'] + '/' + index['path']] = (
                {key: index[key] for key in ('blob', 'sha256', 'size')}, MAX_INDEX)
        for row in lock['packages']:
            if row['repository'] == repo['id']:
                expected[prefix + row['filename']] = ({key: row[key] for key in ('blob', 'sha256', 'size')}, MAX_ARCHIVE)
    found = set()
    stack = [input_path(directory, 'mirrors')]
    while stack:
        folder = stack.pop()
        require(stat.S_ISDIR(folder.lstat().st_mode) and not folder.is_symlink(), 'prepared mirror directory is unsafe')
        for path in folder.iterdir():
            deadline.check()
            name = path.relative_to(directory).as_posix()
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                stack.append(path)
            else:
                require(stat.S_ISREG(info.st_mode) and name in expected, 'prepared mirror contains an unlocked input')
                value, limit = expected[name]
                require(file_identity(input_path(directory, name), limit, deadline) ==
                        {key: value[key] for key in ('sha256', 'size')}, 'prepared mirror differs from its authenticated input')
                found.add(name)
    require(found == set(expected), 'prepared mirror is incomplete')


def verify_prepared(prepared_dir, approved_builder_image_sha256, _deadline=None):
    deadline = _deadline or Deadline(PREPARE_SECONDS)
    prepared_dir = private_directory(prepared_dir)
    lock_bytes = read_regular(prepared_dir / 'inputs-lock.json', MAX_LOCK, deadline)
    lock = decode(lock_bytes)
    if INPUT_PROFILE is not None and deadline.capacity is None:
        with INPUT_PROFILE.admission(prepared_dir.parent, deadline, 'verify-prepared'):
            return verify_prepared(prepared_dir, approved_builder_image_sha256, _deadline=deadline)
    inventory, signatures = verify_inputs(lock, prepared_dir / 'input-cache', approved_builder_image_sha256, deadline)
    verify_mirrors(prepared_dir, lock, deadline)
    receipt = decode(read_regular(prepared_dir / 'prepared.json', MAX_LOCK, deadline))
    expected = {'schema': 1, 'arch': lock['arch'], 'inputs_lock_sha256': digest(lock_bytes),
                'source_inventory_sha256': digest(canonical(inventory) + b'\n'),
                'approved_builder_image_sha256': approved_builder_image_sha256, 'signatures': signatures,
                'full_ready': False, 'reproducibility_verified': False}
    profile = INPUT_PROFILE.verify(prepared_dir, lock, deadline) if INPUT_PROFILE is not None else None
    if profile is not None:
        expected['profile_proof_sha256'] = profile['sha256']
    require(receipt == expected and read_regular(prepared_dir / 'source-inventory.json', MAX_LOCK, deadline) == canonical(inventory) + b'\n', 'prepared receipt/inventory differs from authenticated inputs')
    result = {'schema': 1, 'arch': lock['arch'], 'lock': lock, 'directory': str(prepared_dir),
            'inputs_lock_sha256': digest(lock_bytes), 'source_inventory_sha256': expected['source_inventory_sha256'],
            'source_inventory': inventory, 'build_tool_sha256': file_identity(__file__, MAX_LOCK, deadline)['sha256'],
            'approved_builder_image_sha256': approved_builder_image_sha256}
    if profile is not None:
        result.update(profile_proof=profile['proof'], profile_proof_bytes=profile['bytes'],
                      profile_proof_sha256=profile['sha256'])
    return result


def build_plan(prepared, tree):
    lock = prepared['lock']
    directory = Path(prepared['directory'])
    require(re.fullmatch(r'/[A-Za-z0-9/_+.-]+', str(directory))
            and re.fullmatch(r'/[A-Za-z0-9/_+.-]+', str(tree)), 'build paths cannot contain APT source or hook syntax')
    mirrors = []
    for repo in lock['repositories']:
        mirror = directory / 'mirrors' / repo['id']
        keyring = mirror / 'bookworm-archive-keyring.gpg'
        require(mirror.is_dir() and not mirror.is_symlink(), 'prepared mirror is missing')
        signers = ','.join(sorted(SIGNERS[repo['archive']]))
        mirrors.append('deb [arch=' + lock['arch'] + ' check-valid-until=no signed-by=' + str(keyring) + ',' + signers + '] '
                       + mirror.as_uri() + ' ' + repo['suite'] + ' main')
    # Root mode is confined to a new mount/network/PID namespace on a dedicated
    # native builder. No chrootless mode, online mirrors or unreviewed hooks.
    return ['/usr/bin/unshare', '--mount', '--net', '--pid', '--uts', '--ipc',
            '--mount-proc', '--fork', '--kill-child',
            '/usr/bin/mmdebstrap', '--mode=root', '--variant=essential', '--format=directory',
            '--architectures=' + lock['arch'], '--include=' + ','.join(row['name'] + '=' + row['version'] for row in lock['packages']),
            '--aptopt=APT::Install-Recommends "false"', '--aptopt=Acquire::Retries "0"',
            '--aptopt=Acquire::AllowInsecureRepositories "false"',
            '--aptopt=Acquire::AllowDowngradeToInsecureRepositories "false"',
            '--dpkgopt=path-exclude=/usr/share/man/*', '--dpkgopt=path-exclude=/usr/share/locale/*',
            '--dpkgopt=path-include=/usr/share/locale/locale.alias',
            '--hook-dir=/usr/share/mmdebstrap/hooks/file-mirror-automount',
            'bookworm', str(tree), *mirrors]


def installed_packages(tree, prepared):
    return verify_installed_packages(read_regular(input_path(tree, 'var/lib/dpkg/status'), MAX_LOCK),
                                     prepared['lock']['packages'], exact_sources=INPUT_PROFILE is not None)


def verify_installed_packages(content, packages, exact_sources=False):
    """Check actual dpkg records without executing or extracting the rootfs."""
    rows = list(control_records(content))
    installed = [row for row in rows if row.get('Status') == 'install ok installed']
    actual = {(row.get('Package'), row.get('Version'), row.get('Architecture')) for row in installed}
    expected = {(row['name'], row['version'], row['architecture']) for row in packages}
    require(actual == expected, 'installed packages differ from the authenticated fixed closure')
    if exact_sources:
        require(len(installed) == len(actual) and len(installed) == len(rows),
                'minimal package status contains duplicate or uninstalled records')
        source_pairs = {row['name']: (row['source_name'], row['source_version']) for row in packages}
        for row in installed:
            require(source_pair(row) == source_pairs[row['Package']],
                    'installed package corresponding source differs from the minimal closure')
    return [{'name': name, 'version': version, 'architecture': arch} for name, version, arch in sorted(actual)]


def tree_entries(tree, deadline):
    tree = private_directory(tree)
    entries, paths, expanded = [], {}, 0
    stack = [tree]
    while stack:
        directory = stack.pop()
        for path in sorted(directory.iterdir()):
            deadline.check()
            name = relative(path.relative_to(tree).as_posix())
            require(name != META_DIR and not name.startswith(META_DIR + '/'), 'tree already contains provenance metadata')
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                entry = {'path': name, 'type': 'dir', 'mode': 0o700 if not info.st_mode & 0o077 else 0o755}
                stack.append(path)
            elif stat.S_ISREG(info.st_mode):
                identity = file_identity(path, MAX_ARCHIVE, deadline)
                mode = 0o755 if info.st_mode & 0o111 else (0o644 if info.st_mode & 0o044 else 0o600)
                entry = {'path': name, 'type': 'file', 'mode': mode, **identity}
                expanded += identity['size']
                require(expanded <= MAX_EXPANDED, 'rootfs exceeds expanded size budget')
            elif stat.S_ISLNK(info.st_mode):
                entry = {'path': name, 'type': 'symlink', 'target': os.readlink(path)}
            else:
                raise ValueError('rootfs contains a device/fifo/socket/unsupported member')
            require(len(entries) < MAX_MEMBERS, 'rootfs member count exceeds limit')
            entries.append(entry)
            paths[name] = entry
    for entry in entries:
        if entry['type'] == 'symlink':
            target = resolve_link(entry['path'], entry['target'], paths)
            entry['target'] = posixpath.relpath(target, posixpath.dirname(entry['path']) or '.')
            require(len(entry['target'].encode('ascii')) <= 100, 'symlink cannot be represented by USTAR')
    entries.sort(key=lambda entry: entry['path'])
    return entries


def resolve_link(name, target, paths):
    require(isinstance(target, str) and target and '\\' not in target and target.isascii(), 'invalid tree symlink')
    value = posixpath.normpath(target.lstrip('/') if target.startswith('/') else posixpath.join(posixpath.dirname(name), target))
    seen = set()
    for _ in range(64):
        require(value not in seen and value not in ('.', '..') and not value.startswith('../'), 'escaping/cyclic rootfs symlink')
        seen.add(value)
        parts = value.split('/')
        for index in range(len(parts)):
            prefix = '/'.join(parts[:index + 1])
            entry = paths.get(prefix)
            require(entry is not None, 'dangling rootfs symlink')
            if entry['type'] == 'symlink':
                link = entry['target']
                replacement = link.lstrip('/') if link.startswith('/') else posixpath.join(posixpath.dirname(prefix), link)
                value = posixpath.normpath(posixpath.join(replacement, *parts[index + 1:]))
                break
            require(index == len(parts) - 1 or entry['type'] == 'dir', 'symlink target has a non-directory parent')
        else:
            require(paths[value]['type'] in ('file', 'dir'), 'symlink does not resolve to an ordinary member')
            return value
    raise ValueError('rootfs symlink chain exceeds limit')


def normalize_created_tree(tree):
    # Only called for the newly built, owned tree after mmdebstrap has reaped.
    tree = private_directory(tree)
    ensure_no_mounts(tree)
    for name in ('var/log', 'var/cache/apt', 'var/lib/apt/lists'):
        path = input_path(tree, name)
        if path.exists():
            require(path.is_dir() and not path.is_symlink(), 'generated cache/log directory is unsafe')
            for child in path.iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
    for name, content in (('etc/machine-id', b''), ('etc/resolv.conf', b''),
                          ('etc/hostname', b'sinan-diagnostic\n'),
                          ('etc/hosts', b'127.0.0.1 localhost\n::1 localhost\n')):
        path = input_path(tree, name)
        if path.is_symlink():
            path.unlink()
        path.write_bytes(content)
    # proc/sys/dev are populated only by controlled runtime mounts, never by
    # exporting host device nodes or bootstrap bind-mount contents.
    for name in ('proc', 'sys', 'dev'):
        path = tree / name
        require(path.is_dir() and not path.is_symlink(), 'bootstrap left an unsafe mount directory')
        for child in path.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    for name in ('root/.ssh', 'root/.gnupg', 'home'):
        path = tree / name
        require(not path.exists() or (path.is_dir() and not path.is_symlink() and not any(path.iterdir())), 'rootfs contains private account state')


def build(prepared_dir, output, approved_image, max_output_bytes=DEFAULT_MAX_OUTPUT,
          reserve_free_bytes=DEFAULT_RESERVE_FREE, reserve_free_inodes=DEFAULT_RESERVE_INODES):
    deadline = Deadline(BUILD_SECONDS)
    prepared_dir = private_directory(prepared_dir)
    lock = decode(read_regular(prepared_dir / 'inputs-lock.json', MAX_LOCK, deadline))
    validate_lock(lock)
    native = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    require(sys.platform == 'linux' and os.geteuid() == 0 and native == lock['arch'], 'build requires a dedicated native root Debian Linux builder')
    release_path = Path('/etc/os-release')
    if release_path.is_symlink():
        require(release_path.resolve(strict=True) == Path('/usr/lib/os-release'), 'unexpected builder OS identity link')
        release_path = Path('/usr/lib/os-release')
    release = read_regular(release_path, 65536, deadline).decode('utf-8')
    fields = {}
    for line in release.splitlines():
        if not line or line.startswith('#'):
            continue
        require('=' in line, 'invalid builder OS identity')
        key, value = line.split('=', 1)
        require(key not in fields, 'duplicate builder OS identity field')
        fields[key] = value.strip('"\'')
    require(fields.get('ID') == 'debian' and fields.get('VERSION_ID') == '12', 'native builder must run Debian 12')
    verify_tools(lock, approved_image, set(TOOL_PATHS), deadline)
    capacity_plan_value = admit_factory('build', lock, output, max_output_bytes, reserve_free_bytes, reserve_free_inodes)
    requested_output, output = output, None
    capacity, owned_identity, evidence = None, None, None
    complete = False
    try:
        with deferred_signals():
            output = reserve_output(requested_output)
            owned_identity = FactoryCapacity.identity(output), FactoryCapacity.identity(output.parent)
            capacity = FactoryCapacity(output, capacity_plan_value, deadline)
        deadline.capacity = capacity
        capacity.write(output / 'capacity-plan.json', canonical(capacity_plan_value) + b'\n')
        prepared = verify_prepared(prepared_dir, approved_image, _deadline=deadline)
        if INPUT_PROFILE is not None:
            capacity = deadline.capacity
        tree = output / 'tree'
        plan = build_plan(prepared, tree)
        capacity.write(output / 'build-plan.json', canonical({'schema': 1, 'argv': plan, 'source_epoch': lock['source_epoch']}) + b'\n')
        log = run_bounded(plan, deadline, MAX_LOCK, extra_env={
            'SOURCE_DATE_EPOCH': str(lock['source_epoch']), 'DEBIAN_FRONTEND': 'noninteractive'})
        capacity.write(output / 'build.log', log, 0o600)
        normalize_created_tree(tree)
        installed = installed_packages(tree, prepared)
        entries = tree_entries(tree, deadline)
        receipt = {'schema': 1, 'arch': lock['arch'], 'inputs_lock_sha256': prepared['inputs_lock_sha256'],
                   'source_inventory_sha256': prepared['source_inventory_sha256'], 'build_tool_sha256': prepared['build_tool_sha256'],
                   'builder': lock['builder'], 'tree_entries_sha256': digest(canonical(entries)), 'installed_packages': installed,
                   'build_log_sha256': digest(log), 'full_ready': False, 'reproducibility_verified': False}
        if INPUT_PROFILE is not None:
            receipt['profile_proof_sha256'] = prepared['profile_proof_sha256']
        capacity.write(output / 'build-receipt.json', canonical(receipt) + b'\n')
        capacity.finish()
        complete = True
        return receipt
    except BaseException as error:
        if output is not None:
            evidence = preserve_factory_failure(output, 'build', error, deadline.capacity if INPUT_PROFILE is not None else capacity)
        raise
    finally:
        if not complete and output is not None:
            removed = cleanup_output(output, guard_mounts=True, capacity=capacity, expected_identity=owned_identity)
            if evidence is None and removed and sys.exc_info()[1] is not None:
                evidence = preserve_factory_failure(output, 'build', sys.exc_info()[1], deadline.capacity if INPUT_PROFILE is not None else capacity)
            record_factory_cleanup(evidence, removed, sys.exc_info()[1])


def license_inventory(tree, entries, installed):
    paths = {entry['path']: entry for entry in entries}
    files = []
    for entry in entries:
        name = entry['path']
        if entry['type'] == 'file' and (name.startswith('usr/share/common-licenses/')
                or (name.startswith(('usr/share/doc/', 'usr/share/licenses/'))
                    and re.search(r'(copyright|copying|licen[cs]e)(\.[A-Za-z0-9_-]+)?$', name, re.I))):
            files.append({key: entry[key] for key in ('path', 'sha256', 'size')})
    for package in installed:
        name = 'usr/share/doc/' + package['name'] + '/copyright'
        require(name in paths, 'an installed package lacks its copyright record')
        target = resolve_link(name, paths[name]['target'], paths) if paths[name]['type'] == 'symlink' else name
        require(paths[target]['type'] == 'file' and any(row['path'] == target for row in files), 'package copyright does not resolve to preserved ordinary text')
    tools = []
    for command, package in sorted(TOOL_PACKAGES.items()):
        candidates = [prefix + '/' + command for prefix in ('usr/bin', 'usr/sbin', 'bin', 'sbin')]
        for candidate in candidates:
            try:
                target = resolve_link(candidate, '/' + candidate, paths)
            except ValueError:
                continue
            entry = paths[target]
            if entry['type'] == 'file' and entry['mode'] == 0o755:
                tools.append({'command': command, 'package': package, 'path': target,
                              'sha256': entry['sha256'], 'size': entry['size']})
                break
        else:
            raise ValueError('an open-source base command is missing or not executable: ' + command)
    return {'schema': 1, 'reviewed': False, 'packages': installed, 'files': files, 'tools': tools}


class CheckedReader:
    """Tar receives only the already inventoried number of bytes, with a deadline."""
    def __init__(self, stream, entry, deadline):
        self.stream, self.entry, self.deadline = stream, entry, deadline
        self.length, self.value = 0, hashlib.sha256()

    def read(self, size):
        self.deadline.check()
        data = self.stream.read(min(size, 65536))
        self.length += len(data)
        require(self.length <= self.entry['size'], 'exported tree file grew')
        self.value.update(data)
        return data

    def finish(self):
        self.deadline.check()
        require(not self.stream.read(1) and self.length == self.entry['size']
                and self.value.hexdigest() == self.entry['sha256'], 'exported tree file changed')


class CapacityWriter:
    def __init__(self, stream, capacity, limit):
        self.stream, self.capacity, self.limit = stream, capacity, limit

    def write(self, content):
        require(self.stream.tell() + len(content) <= self.limit, 'rootfs exceeds remaining outer archive budget')
        self.capacity.check(additional_bytes=len(content) + self.capacity.plan['block_size'])
        count = self.stream.write(content)
        require(count == len(content), 'short rootfs archive write')
        return count

    def tell(self):
        return self.stream.tell()

    def flush(self):
        return self.stream.flush()


def export(tree, prepared_dir, output, approved_image, outer_reserve_bytes,
           max_output_bytes=DEFAULT_MAX_OUTPUT, reserve_free_bytes=DEFAULT_RESERVE_FREE,
           reserve_free_inodes=DEFAULT_RESERVE_INODES):
    deadline = Deadline(EXPORT_SECONDS)
    require(type(outer_reserve_bytes) is int and 0 < outer_reserve_bytes < MAX_ARCHIVE, 'explicit outer runner/license/tar reserve required')
    directory = private_directory(prepared_dir)
    lock = decode(read_regular(directory / 'inputs-lock.json', MAX_LOCK, deadline))
    validate_lock(lock)
    verify_tools(lock, approved_image, {'gpgv'}, deadline)
    plan = admit_factory('export', lock, output, max_output_bytes, reserve_free_bytes, reserve_free_inodes)
    requested_output, output = output, None
    capacity, owned_identity, evidence = None, None, None
    complete = False
    try:
        with deferred_signals():
            output = reserve_output(requested_output)
            owned_identity = FactoryCapacity.identity(output), FactoryCapacity.identity(output.parent)
            capacity = FactoryCapacity(output, plan, deadline)
        deadline.capacity = capacity
        capacity.write(output / 'capacity-plan.json', canonical(plan) + b'\n')
        result = export_into(tree, prepared_dir, output, approved_image, outer_reserve_bytes, deadline, capacity)
        if INPUT_PROFILE is not None:
            capacity = deadline.capacity
        capacity.finish()
        complete = True
        return result
    except BaseException as error:
        if output is not None:
            evidence = preserve_factory_failure(output, 'export', error, deadline.capacity if INPUT_PROFILE is not None else capacity)
        raise
    finally:
        if not complete and output is not None:
            removed = cleanup_output(output, guard_mounts=sys.platform == 'linux', capacity=capacity,
                                     expected_identity=owned_identity)
            if evidence is None and removed and sys.exc_info()[1] is not None:
                evidence = preserve_factory_failure(output, 'export', sys.exc_info()[1], deadline.capacity if INPUT_PROFILE is not None else capacity)
            record_factory_cleanup(evidence, removed, sys.exc_info()[1])


def export_into(tree, prepared_dir, output, approved_image, outer_reserve_bytes, deadline, capacity):
    prepared = verify_prepared(prepared_dir, approved_image, _deadline=deadline)
    if INPUT_PROFILE is not None:
        capacity = deadline.capacity
    tree = private_directory(tree)
    entries = tree_entries(tree, deadline)
    installed = installed_packages(tree, prepared)
    build_receipt = decode(read_regular(tree.parent / 'build-receipt.json', MAX_LOCK, deadline))
    build_fields = {'schema', 'arch', 'inputs_lock_sha256',
            'source_inventory_sha256', 'build_tool_sha256', 'builder', 'tree_entries_sha256',
            'installed_packages', 'build_log_sha256', 'full_ready', 'reproducibility_verified'}
    if INPUT_PROFILE is not None:
        build_fields.add('profile_proof_sha256')
    require(isinstance(build_receipt, dict) and set(build_receipt) == build_fields
            and build_receipt.get('schema') == 1 and build_receipt.get('arch') == prepared['arch']
            and build_receipt.get('inputs_lock_sha256') == prepared['inputs_lock_sha256']
            and build_receipt.get('source_inventory_sha256') == prepared['source_inventory_sha256']
            and build_receipt.get('build_tool_sha256') == prepared['build_tool_sha256']
            and build_receipt.get('tree_entries_sha256') == digest(canonical(entries))
            and build_receipt.get('installed_packages') == installed
            and build_receipt.get('builder') == prepared['lock']['builder']
            and build_receipt.get('build_log_sha256') == file_identity(tree.parent / 'build.log', MAX_LOCK, deadline)['sha256']
            and build_receipt.get('full_ready') is False and build_receipt.get('reproducibility_verified') is False,
            'tree lacks the matching preparation build receipt')
    if INPUT_PROFILE is not None:
        require(build_receipt['profile_proof_sha256'] == prepared['profile_proof_sha256'],
                'tree belongs to another minimal input profile')
    require(type(outer_reserve_bytes) is int and 0 < outer_reserve_bytes < MAX_ARCHIVE, 'explicit outer runner/license/tar reserve required')
    licenses = license_inventory(tree, entries, installed)
    lock_bytes = read_regular(Path(prepared['directory']) / 'inputs-lock.json', MAX_LOCK, deadline)
    source_bytes = canonical(prepared['source_inventory']) + b'\n'
    license_bytes = canonical(licenses) + b'\n'
    provenance = {'schema': 1, 'kind': PROVENANCE_KIND, 'arch': prepared['arch'], 'full_ready': False,
                  'source_authenticated': True, 'reproducibility_verified': False,
                  'source_epoch': prepared['lock']['source_epoch'], 'builder': prepared['lock']['builder'],
                  'inputs_lock_sha256': digest(lock_bytes), 'source_inventory_sha256': digest(source_bytes),
                  'license_inventory_sha256': digest(license_bytes), 'build_tool_sha256': prepared['build_tool_sha256'],
                  'pending_capabilities': PENDING}
    if INPUT_PROFILE is not None:
        provenance['profile_proof_sha256'] = prepared['profile_proof_sha256']
    virtual = {META_DIR + '/provenance.json': canonical(provenance) + b'\n',
               META_DIR + '/inputs-lock.json': lock_bytes, META_DIR + '/source-inventory.json': source_bytes,
               META_DIR + '/license-inventory.json': license_bytes}
    if INPUT_PROFILE is not None:
        virtual[META_DIR + '/ipquality-profile.json'] = prepared['profile_proof_bytes']
    require(all(len(content) <= MAX_METADATA for content in virtual.values()), 'embedded provenance/inventory exceeds 1 MiB')
    paths = {entry['path']: entry for entry in entries}
    for parent in ('usr', 'usr/share', META_DIR):
        if parent not in paths:
            entries.append({'path': parent, 'type': 'dir', 'mode': 0o755})
            paths[parent] = entries[-1]
        else:
            require(paths[parent]['type'] == 'dir', 'provenance parent must be an ordinary directory')
    for name, content in virtual.items():
        entries.append({'path': name, 'type': 'file', 'mode': 0o644, 'size': len(content), 'sha256': digest(content)})
    entries.sort(key=lambda entry: entry['path'])
    require(len(entries) <= MAX_MEMBERS, 'export member count exceeds limit')
    expanded = sum(entry.get('size', 0) for entry in entries)
    stream_size = sum(512 + ((entry.get('size', 0) + 511) // 512) * 512 for entry in entries) + 1024
    stream_size += (-stream_size) % 10240
    require(expanded <= MAX_EXPANDED and stream_size <= MAX_STREAM, 'export expansion/tar stream budget exceeded')
    with contextlib.ExitStack():
        archive_path = output / 'rootfs.tar.gz'
        with archive_path.open('xb', buffering=0) as destination:
            bounded_destination = CapacityWriter(destination, capacity, MAX_ARCHIVE - outer_reserve_bytes)
            with gzip.GzipFile(filename='', mode='wb', fileobj=bounded_destination, mtime=0, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                    for entry in entries:
                        deadline.check()
                        member = tarfile.TarInfo(entry['path'])
                        member.uid = member.gid = 0
                        member.uname = member.gname = ''
                        member.mtime = prepared['lock']['source_epoch']
                        member.mode = entry.get('mode', 0o777)
                        if entry['type'] == 'dir':
                            member.type = tarfile.DIRTYPE
                            archive.addfile(member)
                        elif entry['type'] == 'symlink':
                            member.type = tarfile.SYMTYPE
                            member.linkname = entry['target']
                            archive.addfile(member)
                        else:
                            member.size = entry['size']
                            if entry['path'] in virtual:
                                archive.addfile(member, io.BytesIO(virtual[entry['path']]))
                            else:
                                with open_regular(input_path(tree, entry['path']), MAX_ARCHIVE)[0] as source:
                                    reader = CheckedReader(source, entry, deadline)
                                    archive.addfile(member, reader)
                                    reader.finish()
                        require(destination.tell() <= MAX_ARCHIVE - outer_reserve_bytes, 'rootfs exceeds remaining outer archive budget')
        capacity.check(force=True)
        archive_identity = file_identity(archive_path, MAX_ARCHIVE, deadline)
        manifest = {'schema': 1, 'arch': prepared['arch'], 'archive': archive_identity,
                    'expanded_size': expanded, 'stream_size': stream_size,
                    'entries_sha256': digest(canonical(entries)), 'entries': entries}
        manifest_bytes = canonical(manifest) + b'\n'
        require(len(manifest_bytes) <= MAX_LOCK, 'export manifest exceeds byte limit')
        capacity.write(output / 'rootfs-manifest.json', manifest_bytes)
        require(archive_identity['size'] + len(manifest_bytes) + outer_reserve_bytes <= MAX_ARCHIVE,
                'rootfs plus manifest/reserved outer members exceeds 256 MiB')
        for name, content in virtual.items():
            capacity.write(output / PurePosixPath(name).name, content)
        receipt = {'schema': 1, 'arch': prepared['arch'], 'archive': archive_identity,
                   'manifest': {'sha256': digest(manifest_bytes), 'size': len(manifest_bytes)},
                   'inputs_lock_sha256': prepared['inputs_lock_sha256'], 'source_inventory_sha256': digest(source_bytes),
                   'license_inventory_sha256': digest(license_bytes), 'provenance_sha256': digest(canonical(provenance) + b'\n'),
                   'build_tool_sha256': prepared['build_tool_sha256'], 'outer_reserve_bytes': outer_reserve_bytes,
                   'full_ready': False, 'reproducibility_verified': False}
        if INPUT_PROFILE is not None:
            receipt['profile_proof_sha256'] = prepared['profile_proof_sha256']
        capacity.write(output / 'export-receipt.json', canonical(receipt) + b'\n')
        return receipt


def verify_export(rootfs_directory, prepared, arch, _deadline=None):
    deadline = _deadline or Deadline(EXPORT_SECONDS)
    directory = private_directory(rootfs_directory)
    if INPUT_PROFILE is not None and deadline.capacity is None:
        with INPUT_PROFILE.admission(directory.parent, deadline, 'verify-export'):
            return verify_export(rootfs_directory, prepared, arch, _deadline=deadline)
    if INPUT_PROFILE is not None:
        authenticated = verify_prepared(prepared['directory'], prepared['approved_builder_image_sha256'], _deadline=deadline)
        require(authenticated == prepared, 'export preparation differs from fresh minimal profile admission')
    require(arch in ARCHES and arch == prepared['arch'], 'export architecture mismatch')
    receipt = decode(read_regular(directory / 'export-receipt.json', MAX_LOCK, deadline))
    fields = {'schema', 'arch', 'archive', 'manifest', 'inputs_lock_sha256', 'source_inventory_sha256',
              'license_inventory_sha256', 'provenance_sha256', 'build_tool_sha256', 'outer_reserve_bytes',
              'full_ready', 'reproducibility_verified'}
    if INPUT_PROFILE is not None:
        fields.add('profile_proof_sha256')
    require(isinstance(receipt, dict) and set(receipt) == fields and receipt['schema'] == 1 and receipt['arch'] == arch,
            'invalid export receipt')
    require(receipt['full_ready'] is False and receipt['reproducibility_verified'] is False, 'preparation cannot claim full/reproducible certification')
    for name, key, limit in (('rootfs.tar.gz', 'archive', MAX_ARCHIVE), ('rootfs-manifest.json', 'manifest', MAX_LOCK)):
        require(receipt[key] == file_identity(directory / name, limit, deadline), 'exported artifact differs from its receipt')
    inventory_files = [('inputs-lock.json', 'inputs_lock_sha256'), ('source-inventory.json', 'source_inventory_sha256'),
                       ('license-inventory.json', 'license_inventory_sha256'), ('provenance.json', 'provenance_sha256')]
    if INPUT_PROFILE is not None:
        inventory_files.append(('ipquality-profile.json', 'profile_proof_sha256'))
        require(receipt['profile_proof_sha256'] == prepared['profile_proof_sha256'],
                'export belongs to another minimal input profile')
        proof = decode(read_regular(directory / 'ipquality-profile.json', MAX_METADATA, deadline))
        INPUT_PROFILE.validate_public(proof, prepared['lock'], deadline)
        require(proof == prepared['profile_proof'], 'export changed the exact minimal profile')
    for name, key in inventory_files:
        require(file_identity(directory / name, MAX_LOCK, deadline)['sha256'] == receipt[key], 'exported inventory/provenance checksum mismatch')
    require(receipt['inputs_lock_sha256'] == prepared['inputs_lock_sha256']
            and receipt['source_inventory_sha256'] == prepared['source_inventory_sha256']
            and receipt['build_tool_sha256'] == prepared['build_tool_sha256'], 'export does not match authenticated preparation/tool')
    manifest = decode(read_regular(directory / 'rootfs-manifest.json', MAX_LOCK, deadline))
    require(isinstance(manifest, dict) and set(manifest) == {'schema', 'arch', 'archive', 'expanded_size',
            'stream_size', 'entries_sha256', 'entries'} and manifest['schema'] == 1
            and manifest.get('arch') == arch and manifest.get('archive') == receipt['archive']
            and isinstance(manifest['entries'], list) and 0 < len(manifest['entries']) <= MAX_MEMBERS
            and manifest['entries_sha256'] == digest(canonical(manifest['entries'])),
            'export manifest archive/entries binding mismatch')
    metadata = {entry['path']: entry for entry in manifest.get('entries', []) if isinstance(entry, dict)}
    for name, key in inventory_files:
        entry = metadata.get(META_DIR + '/' + name)
        require(entry is not None and entry.get('type') == 'file' and entry.get('sha256') == receipt[key],
                'inventory/provenance is not bound into runtime manifest')
        require(entry.get('size') == len(read_regular(directory / name, MAX_METADATA, deadline)),
                'embedded inventory/provenance size differs from its sidecar')
    provenance = decode(read_regular(directory / 'provenance.json', MAX_LOCK, deadline))
    expected_provenance = {'schema': 1, 'kind': PROVENANCE_KIND, 'arch': arch, 'full_ready': False,
            'source_authenticated': True, 'reproducibility_verified': False,
            'source_epoch': prepared['lock']['source_epoch'], 'builder': prepared['lock']['builder'],
            'inputs_lock_sha256': prepared['inputs_lock_sha256'], 'source_inventory_sha256': prepared['source_inventory_sha256'],
            'license_inventory_sha256': receipt['license_inventory_sha256'], 'build_tool_sha256': prepared['build_tool_sha256'],
            'pending_capabilities': PENDING}
    if INPUT_PROFILE is not None:
        expected_provenance['profile_proof_sha256'] = prepared['profile_proof_sha256']
    require(provenance == expected_provenance, 'unrecognized preparation provenance')
    reserve = receipt['outer_reserve_bytes']
    require(type(reserve) is int and 0 < reserve < MAX_ARCHIVE
            and receipt['archive']['size'] + receipt['manifest']['size'] + reserve <= MAX_ARCHIVE,
            'export exceeds fixed outer budget')
    if INPUT_PROFILE is not None:
        INPUT_PROFILE.verify_export(directory, manifest, prepared, deadline)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    plan_parser = commands.add_parser('plan', help='schema-only capacity planning; no authentication or approval')
    plan_parser.add_argument('--materials', type=Path, required=True)
    plan_parser.add_argument('--phase', choices=('prepare', 'build', 'export'), required=True)
    plan_parser.add_argument('--output-parent', type=Path, required=True)
    prepare_parser = commands.add_parser('prepare')
    prepare_parser.add_argument('--lock', type=Path, required=True)
    prepare_parser.add_argument('--cache', type=Path, required=True)
    prepare_parser.add_argument('--output', type=Path, required=True)
    build_parser = commands.add_parser('build')
    build_parser.add_argument('--prepared', type=Path, required=True)
    build_parser.add_argument('--output', type=Path, required=True)
    export_parser = commands.add_parser('export')
    export_parser.add_argument('--tree', type=Path, required=True)
    export_parser.add_argument('--prepared', type=Path, required=True)
    export_parser.add_argument('--output', type=Path, required=True)
    export_parser.add_argument('--outer-reserve-bytes', type=int, required=True)
    for value in (prepare_parser, build_parser, export_parser):
        value.add_argument('--approved-builder-image-sha256', required=True)
    for value in (plan_parser, prepare_parser, build_parser, export_parser):
        value.add_argument('--max-output-bytes', type=int, default=DEFAULT_MAX_OUTPUT)
        value.add_argument('--reserve-free-bytes', type=int, default=DEFAULT_RESERVE_FREE)
        value.add_argument('--reserve-free-inodes', type=int, default=DEFAULT_RESERVE_INODES)
    args = parser.parse_args()
    capacity_options = (args.max_output_bytes, args.reserve_free_bytes, args.reserve_free_inodes)
    if args.operation == 'plan':
        materials = decode(read_regular(args.materials, MAX_LOCK))
        result = capacity_plan(args.phase, materials, args.output_parent, *capacity_options)
    elif args.operation == 'prepare':
        result = prepare(args.lock, args.cache, args.output, args.approved_builder_image_sha256, *capacity_options)
    elif args.operation == 'build':
        result = build(args.prepared, args.output, args.approved_builder_image_sha256, *capacity_options)
    else:
        result = export(args.tree, args.prepared, args.output, args.approved_builder_image_sha256, args.outer_reserve_bytes, *capacity_options)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        with cli_signals():
            main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('Error: ' + str(error)) from None
