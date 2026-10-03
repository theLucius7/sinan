#!/usr/bin/env python3
"""Inventory rootfs executable identities without extraction or execution."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import time

MAX_ARCHIVE = 512 * 1024 * 1024
MAX_EXPANDED = 8 * 1024 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
MAX_MEMBERS = 100000
MAX_EXECUTABLES = 16384
MAX_DECLARATION = 8 * 1024 * 1024
MAX_EXTENSION = 65536
SECONDS = 240
ARCHITECTURES = {62: 'amd64', 183: 'arm64'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate inventory key')
        result[key] = value
    return result


def ordinary(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(descriptor, 'rb')
    metadata = os.fstat(stream.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
        stream.close()
        raise ValueError('inventory input must be a bounded ordinary file')
    return stream, metadata.st_size


def check_deadline(deadline):
    if time.monotonic() >= deadline:
        raise ValueError('inventory deadline exceeded')


class ExpandedReader:
    def __init__(self, stream, deadline):
        self.stream, self.deadline, self.total = stream, deadline, 0

    def read(self, size):
        check_deadline(self.deadline)
        # Refuse large tar extension headers before buffering their contents.
        if size < 0 or size > 65536:
            raise ValueError('archive read exceeds its block limit')
        content = self.stream.read(size)
        self.total += len(content)
        if self.total > MAX_EXPANDED:
            raise ValueError('expanded archive exceeds its byte limit')
        check_deadline(self.deadline)
        return content


class BoundedTarInfo(tarfile.TarInfo):
    # TarInfo processes these records before the ordinary member is yielded.
    # Bound them before the standard parser buffers names or PAX values.
    def _proc_pax(self, archive):
        if self.size > MAX_EXTENSION:
            raise ValueError('tar extension header exceeds its byte limit')
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive):
        if self.size > MAX_EXTENSION:
            raise ValueError('tar extension header exceeds its byte limit')
        return super()._proc_gnulong(archive)


def member_name(name):
    value = name[:-1] if name.endswith('/') else name
    parts = value.split('/')
    if (not value or value.startswith('/') or parts[0] != 'BenchOs'
            or any(part in ('', '.', '..') for part in parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError('archive member path escapes the fixed rootfs')
    return value


def private_configuration(name):
    parts = PurePosixPath(name).parts
    return ('.ssh' in parts or '.gnupg' in parts or '.config' in parts
            or (len(parts) > 1 and parts[1] in ('root', 'home', 'etc')))


def identity(prefix, mode):
    if prefix.startswith(b'\x7fELF'):
        if len(prefix) < 20 or prefix[4] not in (1, 2) or prefix[5] not in (1, 2):
            raise ValueError('invalid ELF identity header')
        endian = 'little' if prefix[5] == 1 else 'big'
        machine = int.from_bytes(prefix[18:20], endian)
        detected = ARCHITECTURES.get(machine, 'unsupported-' + str(machine))
        return 'elf', detected if prefix[4] == 2 else 'unsupported-class-' + str(prefix[4])
    if prefix.startswith(b'#!'):
        return 'script', 'portable'
    if mode & 0o111:
        return 'executable-other', 'unknown'
    return None, None


def scan(path, architecture, expected_sha256):
    deadline = time.monotonic() + SECONDS
    with ordinary(path, MAX_ARCHIVE)[0] as raw:
        before = os.fstat(raw.fileno())
        digest = hashlib.sha256()
        while content := raw.read(65536):
            check_deadline(deadline)
            digest.update(content)
        actual = digest.hexdigest()
        if actual != expected_sha256:
            raise ValueError('rootfs archive SHA256 mismatch')
        raw.seek(0)
        rows, seen, excluded, unread_executables, links = [], set(), [], [], 0
        with gzip.GzipFile(fileobj=raw) as compressed:
            reader = ExpandedReader(compressed, deadline)
            with tarfile.open(fileobj=reader, mode='r|', tarinfo=BoundedTarInfo, ignore_zeros=True) as archive:
                for member in archive:
                    check_deadline(deadline)
                    name = member_name(member.name)
                    if name in seen or len(seen) >= MAX_MEMBERS:
                        raise ValueError('duplicate member or member limit exceeded')
                    seen.add(name)
                    if member.size < 0 or member.size > MAX_MEMBER:
                        raise ValueError('rootfs member exceeds its byte limit')
                    if member.sparse is not None:
                        raise ValueError('sparse rootfs members are unsupported')
                    if member.isdir():
                        continue
                    if member.issym() or member.islnk():
                        # Never resolve links or interpret them as evidence for
                        # a file. A later full admission needs the entire graph.
                        links += 1
                        continue
                    if not member.isfile():
                        raise ValueError('rootfs contains a special archive member')
                    if private_configuration(name):
                        excluded.append(name)
                        # Retain only tar metadata. An executable in a private
                        # path must be visible as an unresolved omission without
                        # opening configuration or credential file contents.
                        if member.mode & 0o111:
                            if len(unread_executables) >= MAX_EXECUTABLES:
                                raise ValueError('unread executable metadata limit exceeded')
                            unread_executables.append(dict(path=name, size=member.size,
                                                           mode=member.mode & 0o7777))
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValueError('ordinary archive member is unreadable')
                    with stream:
                        prefix = stream.read(min(64, member.size))
                        kind, detected = identity(prefix, member.mode)
                        if kind is None:
                            continue
                        if kind == 'elf' and detected != architecture:
                            raise ValueError('rootfs executable architecture mismatch')
                        if len(rows) >= MAX_EXECUTABLES:
                            raise ValueError('executable inventory limit exceeded')
                        digest = hashlib.sha256(prefix)
                        count = len(prefix)
                        while content := stream.read(65536):
                            check_deadline(deadline)
                            digest.update(content)
                            count += len(content)
                        if count != member.size:
                            raise ValueError('rootfs executable size mismatch')
                    rows.append(dict(path=name, size=member.size, sha256=digest.hexdigest(),
                                     format=kind, architecture=detected))
        after = os.fstat(raw.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('rootfs changed while it was being inventoried')
    return dict(schema=1, architecture=architecture,
                archive=dict(size=before.st_size, sha256=actual),
                files=sorted(rows, key=lambda row: row['path']),
                members=len(seen), links_not_followed=links,
                configuration_files_not_read=len(excluded),
                unread_executable_files=sorted(unread_executables, key=lambda row: row['path']),
                inventory_scope='public-ordinary-executable-identities',
                complete_execution_inventory=False,
                full_start_allowed=False,
                rights_verified=False,
                remaining='Executable metadata in private paths, non-executable files in private paths, link targets, source recipes, tool rights, uploads and host side effects require separate review.')


def declared_identities(path, report):
    with ordinary(path, MAX_DECLARATION)[0] as stream:
        content = stream.read(MAX_DECLARATION + 1)
    if len(content) > MAX_DECLARATION:
        raise ValueError('declared inventory exceeds its byte limit')
    declared = json.loads(content, object_pairs_hook=unique_object)
    if (not isinstance(declared, dict) or set(declared) != {'schema', 'architecture', 'archive', 'files'}
            or type(declared['schema']) is not int or declared['schema'] != 1
            or declared['architecture'] != report['architecture']
            or not isinstance(declared['archive'], dict) or set(declared['archive']) != {'size', 'sha256'}
            or type(declared['archive']['size']) is not int or declared['archive'] != report['archive']
            or not isinstance(declared['files'], list) or len(declared['files']) > MAX_EXECUTABLES):
        raise ValueError('unsupported or mismatching declared rootfs inventory')
    rows = {}
    for row in declared['files']:
        if (not isinstance(row, dict) or set(row) != {'path', 'size', 'sha256', 'format', 'architecture'}
                or not isinstance(row['path'], str) or row['path'] in rows
                or type(row['size']) is not int or not 0 <= row['size'] <= MAX_MEMBER
                or not isinstance(row['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['sha256'])
                or row['format'] not in ('elf', 'script', 'executable-other')
                or not isinstance(row['architecture'], str)):
            raise ValueError('invalid or duplicate declared executable identity')
        member_name(row['path'])
        rows[row['path']] = row
    observed = {row['path']: row for row in report['files']}
    if rows != observed:
        raise ValueError('undeclared, missing or modified rootfs executable')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--architecture', required=True, choices=tuple(ARCHITECTURES.values()))
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--declared-inventory', type=Path)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{64}', args.sha256):
        raise ValueError('archive requires a fixed SHA256 identity')
    report = scan(args.archive, args.architecture, args.sha256)
    if args.declared_inventory:
        declared_identities(args.declared_inventory, report)
    report['executable_identity_declaration_matches'] = args.declared_inventory is not None
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    # Even exact identities cannot authorize proprietary tooling or full runs.
    return 0 if args.declared_inventory else 3


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError, EOFError, tarfile.TarError) as error:
        raise SystemExit('Error: ' + str(error)) from None
