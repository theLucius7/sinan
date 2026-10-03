#!/usr/bin/env python3
"""Verify and prepare a local rootfs already covered by the outer signed artifact.

This helper neither establishes distribution permission nor enables full mode.
It accepts a canonical USTAR gzip and never downloads or executes its contents.
"""
import argparse
import contextlib
import ctypes
import errno
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import posixpath
import re
import signal
import stat
import sys
import time
import uuid
import zlib

MAX_COMPRESSED = 256 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_STREAM = MAX_EXPANDED + 64 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_MANIFEST = 8 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_PATH = 255
BLOCK = 1024 * 1024
DEADLINE_SECONDS = 120
DISK_RESERVE = 64 * 1024 * 1024
DIR_MODES = frozenset((0o700, 0o755))
FILE_MODES = frozenset((0o600, 0o644, 0o755))
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
METADATA_NAMES = frozenset('usr/share/sinan-rootfs/' + name for name in (
    'provenance.json', 'inputs-lock.json', 'source-inventory.json', 'license-inventory.json'))
MAX_METADATA = 1024 * 1024


def _deadline(end):
    if time.monotonic() >= end:
        raise ValueError('rootfs preparation deadline exceeded')


def _path(value):
    if (not isinstance(value, str) or not value or len(value.encode('utf-8')) > MAX_PATH
            or '\\' in value or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or any(part in ('', '.', '..') for part in value.split('/'))):
        raise ValueError('rootfs path must be canonical and relative')
    return value


def _directory(path):
    path = os.fspath(path)
    if not isinstance(path, str) or not path.startswith('/'):
        raise ValueError('rootfs inputs require absolute paths')
    parts = path.split('/')[1:]
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('rootfs input path must be canonical')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextlib.contextmanager
def _ordinary(path, limit):
    path = Path(path)
    parent = _directory(str(path.parent))
    try:
        if path.name in ('', '.', '..'):
            raise ValueError('rootfs input requires a file name')
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= limit):
            raise ValueError('rootfs input must be a bounded ordinary single-link file')
        yield stream, before
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        if any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError('rootfs input changed during verification')


def ordinary(path, limit):
    """Read small metadata; use verify_archive for compressed rootfs bytes."""
    if type(limit) is not int or not 0 < limit <= MAX_MANIFEST:
        raise ValueError('metadata read limit exceeds the rootfs manifest bound')
    end = time.monotonic() + DEADLINE_SECONDS
    with _ordinary(path, limit) as (stream, before):
        chunks, size = [], 0
        while True:
            _deadline(end)
            chunk = stream.read(min(BLOCK, limit - size + 1))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                raise ValueError('rootfs metadata exceeds its byte limit')
        if size != before.st_size:
            raise ValueError('rootfs metadata length changed')
    return b''.join(chunks)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate rootfs manifest key')
        result[key] = value
    return result


def _validate(manifest, arch=None):
    fields = {'schema', 'arch', 'archive', 'expanded_size', 'stream_size',
              'entries_sha256', 'entries'}
    if (not isinstance(manifest, dict) or set(manifest) != fields
            or type(manifest['schema']) is not int or manifest['schema'] != 1
            or manifest['arch'] not in ('amd64', 'arm64')
            or (arch is not None and manifest['arch'] != arch)):
        raise ValueError('unsupported rootfs manifest or architecture')
    archive = manifest['archive']
    if (not isinstance(archive, dict) or set(archive) != {'size', 'sha256'}
            or type(archive['size']) is not int or not 0 < archive['size'] <= MAX_COMPRESSED
            or not isinstance(archive['sha256'], str) or not SHA256.fullmatch(archive['sha256'])):
        raise ValueError('invalid compressed rootfs identity or size')
    entries = manifest['entries']
    if not isinstance(entries, list) or not 0 < len(entries) <= MAX_ENTRIES:
        raise ValueError('rootfs member count exceeds its bound')
    rows, total, minimum = {}, 0, 1024
    for row in entries:
        if not isinstance(row, dict):
            raise ValueError('invalid rootfs member')
        path, kind = _path(row.get('path')), row.get('type')
        if path in rows:
            raise ValueError('duplicate rootfs member path')
        if kind == 'file':
            if (set(row) != {'path', 'type', 'mode', 'size', 'sha256'}
                    or type(row['size']) is not int or not 0 <= row['size'] <= MAX_FILE
                    or not isinstance(row['sha256'], str) or not SHA256.fullmatch(row['sha256'])):
                raise ValueError('invalid rootfs file identity or size')
            total += row['size']
            minimum += (row['size'] + 511) // 512 * 512
        elif kind == 'dir':
            if set(row) != {'path', 'type', 'mode'}:
                raise ValueError('invalid rootfs directory')
        elif kind == 'symlink':
            target = row.get('target')
            if (set(row) != {'path', 'type', 'target'} or not isinstance(target, str)
                    or not target or len(target.encode('utf-8')) > 100 or target.startswith('/')
                    or '\\' in target or any(ord(char) < 32 or ord(char) == 127 for char in target)
                    or any(part in ('', '.') for part in target.split('/'))):
                raise ValueError('rootfs symlink target must be bounded and relative')
        else:
            raise ValueError('rootfs special files and hardlinks are forbidden')
        if kind != 'symlink' and (type(row['mode']) is not int
                                 or row['mode'] not in (DIR_MODES if kind == 'dir' else FILE_MODES)):
            raise ValueError('rootfs mode is outside the safe whitelist')
        rows[path] = row
        minimum += 512
    if list(rows) != sorted(rows):
        raise ValueError('rootfs manifest paths must be sorted')
    for path, row in rows.items():
        parent = posixpath.dirname(path)
        while parent:
            if rows.get(parent, {}).get('type') != 'dir':
                raise ValueError('rootfs parents must be explicit ordinary directories')
            parent = posixpath.dirname(parent)
        if row['type'] == 'symlink':
            target = _path(posixpath.normpath(posixpath.join(posixpath.dirname(path), row['target'])))
            if rows.get(target, {}).get('type') not in ('file', 'dir'):
                raise ValueError('rootfs symlink must resolve to an ordinary manifest member')
    if (type(manifest['expanded_size']) is not int or manifest['expanded_size'] != total
            or total > MAX_EXPANDED or type(manifest['stream_size']) is not int
            or not minimum <= manifest['stream_size'] <= MAX_STREAM
            or manifest['stream_size'] % 512):
        raise ValueError('rootfs expanded or tar stream size exceeds its bound')
    canonical = json.dumps(entries, ensure_ascii=True, sort_keys=True,
                           separators=(',', ':')).encode('ascii')
    if (len(canonical) > MAX_MANIFEST or not isinstance(manifest['entries_sha256'], str)
            or hashlib.sha256(canonical).hexdigest() != manifest['entries_sha256']):
        raise ValueError('rootfs content inventory digest mismatch')
    return rows


def load_manifest(content, arch):
    if not isinstance(content, bytes) or not 0 < len(content) <= MAX_MANIFEST:
        raise ValueError('rootfs manifest exceeds its byte limit')
    if arch not in ('amd64', 'arm64'):
        raise ValueError('unsupported requested rootfs architecture')
    manifest = json.loads(content.decode('utf-8'), object_pairs_hook=_unique)
    _validate(manifest, arch)
    return manifest


class _Compressed:
    def __init__(self, stream, size, end):
        self.stream, self.size, self.end = stream, size, end
        self.count, self.digest = 0, hashlib.sha256()

    def read(self, size=-1):
        _deadline(self.end)
        size = min(BLOCK, self.size - self.count + 1, BLOCK if size < 0 else size)
        data = self.stream.read(size)
        self.count += len(data)
        if self.count > self.size:
            raise ValueError('compressed rootfs exceeds its declared size')
        self.digest.update(data)
        return data


class _Expanded:
    def __init__(self, stream, size, end):
        self.stream, self.size, self.end, self.count = stream, size, end, 0

    def read(self, size):
        _deadline(self.end)
        data = self.stream.read(min(size, BLOCK, self.size - self.count + 1))
        self.count += len(data)
        if self.count > self.size:
            raise ValueError('rootfs tar stream exceeds its declared size')
        return data


def _text(value):
    head, marker, tail = value.partition(b'\0')
    if marker and any(tail):
        raise ValueError('noncanonical rootfs tar text field')
    return head.decode('utf-8')


def _number(value):
    value = value.strip(b' \0')
    if value and not re.fullmatch(b'[0-7]+', value):
        raise ValueError('rootfs numeric fields require unsigned octal')
    return int(value or b'0', 8)


def _header(block):
    if (len(block) != 512 or block[257:263] != b'ustar\0' or block[263:265] != b'00'
            or any(block[500:]) or _number(block[148:156]) != sum(block[:148]) + 256 + sum(block[156:])):
        raise ValueError('rootfs requires valid canonical USTAR headers')
    kind = {b'0': 'file', b'\0': 'file', b'5': 'dir', b'2': 'symlink'}.get(block[156:157])
    if kind is None:
        raise ValueError('rootfs extended headers, special files and hardlinks are forbidden')
    name, prefix = _text(block[:100]), _text(block[345:500])
    path = (prefix + '/' if prefix else '') + name
    path = _path(path[:-1] if kind == 'dir' and path.endswith('/') else path)
    mode, size, target = _number(block[100:108]), _number(block[124:136]), _text(block[157:257])
    for field in (block[108:116], block[116:124], block[136:148]):
        _number(field)
    if _number(block[329:337]) or _number(block[337:345]) or (kind != 'file' and size):
        raise ValueError('rootfs member has forbidden device or content metadata')
    if (kind != 'symlink' and target) or (kind == 'symlink' and mode != 0o777):
        raise ValueError('rootfs link metadata mismatch')
    return path, kind, mode, size, target


def _scan(path, manifest, sink=None, end=None):
    rows, seen = _validate(manifest), set()
    end = time.monotonic() + DEADLINE_SECONDS if end is None else end
    with _ordinary(path, MAX_COMPRESSED) as (source, before):
        if before.st_size != manifest['archive']['size']:
            raise ValueError('compressed rootfs length mismatch')
        compressed = _Compressed(source, before.st_size, end)
        try:
            with gzip.GzipFile(fileobj=compressed, mode='rb') as unzipped:
                stream = _Expanded(unzipped, manifest['stream_size'], end)
                while True:
                    block = stream.read(512)
                    if block == bytes(512):
                        if stream.read(512) != bytes(512):
                            raise ValueError('rootfs requires two tar end blocks')
                        while True:
                            tail = stream.read(BLOCK)
                            if not tail:
                                break
                            if any(tail):
                                raise ValueError('rootfs data after tar end is forbidden')
                        break
                    name, kind, mode, size, target = _header(block)
                    row = rows.get(name)
                    if name in seen or row is None or row['type'] != kind:
                        raise ValueError('rootfs archive has duplicate or unlisted members')
                    seen.add(name)
                    if ((kind == 'file' and (row['size'] != size or row['mode'] != mode))
                            or (kind == 'dir' and row['mode'] != mode)
                            or (kind == 'symlink' and row['target'] != target)):
                        raise ValueError('rootfs member differs from its inventory')
                    if kind == 'file':
                        digest, remaining = hashlib.sha256(), size
                        destination = sink(name) if sink else contextlib.nullcontext(None)
                        with destination as output:
                            while remaining:
                                data = stream.read(min(remaining, BLOCK))
                                if not data:
                                    raise ValueError('truncated rootfs file')
                                remaining -= len(data)
                                digest.update(data)
                                if output is not None:
                                    output.write(data)
                        if digest.hexdigest() != row['sha256']:
                            raise ValueError('rootfs file digest mismatch')
                        padding = stream.read((-size) % 512)
                        if len(padding) != (-size) % 512 or any(padding):
                            raise ValueError('rootfs file padding mismatch')
        except (OSError, EOFError, zlib.error):
            raise ValueError('rootfs compression or local IO verification failed') from None
        if (seen != set(rows) or stream.count != manifest['stream_size']
                or compressed.count != before.st_size
                or compressed.digest.hexdigest() != manifest['archive']['sha256']):
            raise ValueError('rootfs complete stream or inventory identity mismatch')
    _deadline(end)
    return {'schema': 1, 'arch': manifest['arch'], 'archive_size': compressed.count,
            'archive_sha256': compressed.digest.hexdigest(), 'stream_size': stream.count,
            'expanded_size': manifest['expanded_size'], 'entries_sha256': manifest['entries_sha256'],
            'entries': len(rows), **{kind + 's': sum(row['type'] == kind for row in rows.values())
                                   for kind in ('file', 'dir', 'symlink')}}


def verify_archive(path, manifest):
    """Verify the complete gzip/USTAR stream without writing or executing members."""
    return _scan(path, manifest)


def read_metadata(archive_path, manifest, names):
    """Return only fixed small provenance files after complete archive verification."""
    if (not isinstance(names, (list, tuple)) or not 0 < len(names) <= 4
            or any(not isinstance(name, str) or name not in METADATA_NAMES for name in names)
            or len(set(names)) != len(names)):
        raise ValueError('rootfs metadata selection is outside its fixed whitelist')
    rows = _validate(manifest)
    if any(rows.get(name, {}).get('type') != 'file' or rows[name]['size'] > MAX_METADATA
           for name in names):
        raise ValueError('rootfs provenance requires bounded ordinary manifest files')
    captured = {name: io.BytesIO() for name in names}
    _scan(archive_path, manifest, lambda name: contextlib.nullcontext(captured.get(name)))
    return {name: content.getvalue() for name, content in captured.items()}


def _at_directory(root, path):
    descriptor = os.dup(root)
    try:
        for part in path.split('/') if path else ():
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _remove_contents(descriptor):
    for name in os.listdir(descriptor):
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                _remove_contents(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        else:
            os.unlink(name, dir_fd=descriptor)


def _publish(parent, source, destination):
    # Python os.rename can replace an existing empty directory. Fail closed if
    # the Linux atomic no-replace operation is unavailable; never fall back.
    if not sys.platform.startswith('linux'):
        raise ValueError('atomic rootfs publication requires Linux renameat2')
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is None:
        raise ValueError('atomic rootfs publication is unavailable')
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(source), parent, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise ValueError('rootfs destination already exists')
        raise OSError(code, 'atomic rootfs publication failed')


def extract(archive, manifest, workspace, arch, destination='BenchOs'):
    if not isinstance(destination, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', destination):
        raise ValueError('rootfs destination must be one ordinary child name')
    rows = _validate(manifest, arch)
    parent, stage, stage_fd, published = _directory(workspace), None, None, False
    stage_created = False
    end = time.monotonic() + DEADLINE_SECONDS
    try:
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('rootfs workspace must be owned and private with mode 0700')
        try:
            os.stat(destination, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('rootfs destination already exists')
        disk = os.fstatvfs(parent)
        fragment = max(disk.f_frsize, 4096)
        required = DISK_RESERVE + len(rows) * fragment + sum(
            (row['size'] + fragment - 1) // fragment * fragment
            for row in rows.values() if row['type'] == 'file')
        if disk.f_bavail * disk.f_frsize < required:
            raise ValueError('insufficient disk space for bounded rootfs preparation')
        stage = '.rootfs-stage-' + uuid.uuid4().hex
        os.mkdir(stage, 0o700, dir_fd=parent)
        stage_created = True
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        for path, row in sorted(rows.items(), key=lambda item: (item[0].count('/'), item[0])):
            _deadline(end)
            if row['type'] == 'dir':
                owner = _at_directory(stage_fd, posixpath.dirname(path))
                try:
                    os.mkdir(posixpath.basename(path), 0o700, dir_fd=owner)
                finally:
                    os.close(owner)

        @contextlib.contextmanager
        def sink(path):
            owner = _at_directory(stage_fd, posixpath.dirname(path))
            try:
                file_fd = os.open(posixpath.basename(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                  | os.O_NOFOLLOW, 0o600, dir_fd=owner)
            finally:
                os.close(owner)
            with os.fdopen(file_fd, 'wb') as output:
                yield output

        receipt = _scan(archive, manifest, sink, end)
        for path, row in rows.items():
            _deadline(end)
            owner = _at_directory(stage_fd, posixpath.dirname(path))
            try:
                if row['type'] == 'symlink':
                    os.symlink(row['target'], posixpath.basename(path), dir_fd=owner)
                else:
                    file_fd = os.open(posixpath.basename(path), os.O_RDONLY | os.O_NOFOLLOW,
                                      dir_fd=owner)
                    try:
                        os.fchmod(file_fd, row['mode'])
                    finally:
                        os.close(file_fd)
            finally:
                os.close(owner)
        _deadline(end)
        # A handled signal must not land between rename and the committed flag;
        # otherwise cleanup could mistake the published tree for a partial stage.
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK,
                                              {signal.SIGTERM, signal.SIGHUP, signal.SIGINT})
        try:
            _publish(parent, stage, destination)
            published = True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        return {**receipt, 'state': 'prepared', 'destination': destination}
    finally:
        try:
            if stage_fd is not None:
                try:
                    if not published:
                        _remove_contents(stage_fd)
                        os.rmdir(stage, dir_fd=parent)
                finally:
                    os.close(stage_fd)
            elif stage_created:
                os.rmdir(stage, dir_fd=parent)
        finally:
            os.close(parent)


def _interrupted(signum, _frame):
    # TERM/HUP unwind extract's finally. SIGKILL requires outer workspace cleanup.
    raise SystemExit(128 + signum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('verify', 'extract'))
    parser.add_argument('--archive', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--arch', required=True, choices=('amd64', 'arm64'))
    parser.add_argument('--workspace')
    parser.add_argument('--destination', default='BenchOs')
    args = parser.parse_args()
    previous = {signum: signal.signal(signum, _interrupted)
                for signum in (signal.SIGTERM, signal.SIGHUP)}
    try:
        manifest = load_manifest(ordinary(args.manifest, MAX_MANIFEST), args.arch)
        if args.operation == 'extract':
            if args.workspace is None:
                raise ValueError('rootfs extraction requires a private workspace')
            result = extract(args.archive, manifest, args.workspace, args.arch, args.destination)
        else:
            if args.workspace is not None:
                raise ValueError('rootfs verification does not accept a workspace')
            result = verify_archive(args.archive, manifest)
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    except (ValueError, OSError) as error:
        message = str(error) if isinstance(error, ValueError) else 'local rootfs IO refused'
        print('Error: ' + message, file=sys.stderr)
        return 70
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
