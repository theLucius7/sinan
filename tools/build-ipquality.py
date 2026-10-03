#!/usr/bin/env python3
"""Prepare fixed IPQuality, authenticated offline runtime and complete sources.

Unsigned packaging is separate from approval, signing and node acceptance. A
license-review declaration is retained as an attestation, not an approval fact.
"""
import argparse
import contextlib
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
import ipquality_artifact as artifact

BLOCK = 1024 * 1024
DISK_RESERVE = 512 * BLOCK
INODE_RESERVE = 1024
MEMORY_RESERVE = 256 * BLOCK
CHECKSUM_NAMES = {'amd64', 'arm64', 'amd64.sources.tar.gz', 'arm64.sources.tar.gz'}


def memory_available():
    """Observe Linux host headroom and finite enclosing cgroup v2 limits."""
    if sys.platform != 'linux':
        return None
    with open('/proc/meminfo', encoding='ascii') as source:
        values = dict(line.split(':', 1) for line in source.read(65536).splitlines())
    value = values.get('MemAvailable', '').split()
    artifact.ensure(len(value) == 2 and value[1] == 'kB', 'available memory is unknown')
    available = int(value[0]) * 1024
    with open('/proc/self/cgroup', encoding='ascii') as source:
        rows = source.read(65536).splitlines()
    for row in rows:
        if row.startswith('0::'):
            parts = row[3:].split('/')
            artifact.ensure(all(part not in ('.', '..') for part in parts), 'unsafe cgroup identity')
            directory = Path('/sys/fs/cgroup').joinpath(*(part for part in parts if part))
            while directory != Path('/sys/fs'):
                try:
                    maximum = (directory / 'memory.max').read_text(encoding='ascii').strip()
                    current = int((directory / 'memory.current').read_text(encoding='ascii').strip())
                except FileNotFoundError:
                    break
                if maximum != 'max':
                    available = min(available, max(0, int(maximum) - current))
                directory = directory.parent
    return available


def memory_check(additional=0):
    available = memory_available()
    artifact.ensure(available is None or available >= MEMORY_RESERVE + additional,
                    'insufficient available memory for packaging and management reserve')


class Guard:
    def __init__(self, capacity, deadline):
        self.capacity, self.deadline, self.output = capacity, deadline, capacity.output
        self.next_memory = 0

    def __getattr__(self, name):
        return getattr(self.capacity, name)

    def check(self, force=False, additional_bytes=0, additional_inodes=0):
        result = self.capacity.check(force, additional_bytes, additional_inodes)
        if force or time.monotonic() >= self.next_memory:
            memory_check()
            self.next_memory = time.monotonic() + 0.25
        return result

    def progress(self):
        self.deadline.check()


def read(path, limit, guard=None):
    """Immutable ordinary input, including archives larger than metadata limits."""
    with artifact.runtime()._ordinary(Path(path).absolute(), limit) as (source, metadata):
        memory_check(metadata.st_size * 2 + 16 * BLOCK)
        chunks, size = [], 0
        while chunk := source.read(BLOCK):
            if guard:
                guard.progress()
            size += len(chunk)
            artifact.ensure(size <= metadata.st_size, 'ordinary input grew beyond admitted length')
            chunks.append(chunk)
        artifact.ensure(size == metadata.st_size, 'ordinary input length changed')
        return b''.join(chunks)


def identity(path, limit, guard):
    measured, size = hashlib.sha256(), 0
    with artifact.runtime()._ordinary(Path(path).absolute(), limit) as (source, metadata):
        while chunk := source.read(BLOCK):
            guard.progress()
            size += len(chunk)
            artifact.ensure(size <= metadata.st_size, 'ordinary input grew beyond admitted length')
            measured.update(chunk)
        artifact.ensure(size == metadata.st_size, 'ordinary input length changed')
    return {'sha256': measured.hexdigest(), 'size': size}


def private_directory(path):
    """Create explicit owned parents through no-follow directory descriptors."""
    path = Path(path).absolute()
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            try:
                os.mkdir(component, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        artifact.ensure(metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022,
                        'output directory must be privately owned')
    finally:
        os.close(descriptor)
    return path


def tar_size(items):
    size = sum(512 + ((item['size'] + 511) // 512) * 512 for item in items) + 1024
    return size + (-size) % 10240


def corresponding_sources(lock):
    expected = {}
    for row in lock['sources']:
        for item in row['files']:
            name = 'debian-sources/' + item['blob']
            value = {key: item[key] for key in ('size', 'sha256')}
            artifact.ensure(name not in expected or expected[name] == value,
                            'ambiguous corresponding-source blob')
            expected[name] = value
    artifact.ensure(len(expected) + 1 <= 16384, 'too many corresponding-source members')
    return expected


def capacity_plan(factory, root, lock, original_size, args):
    """Upper-bound new bytes only; this never authenticates input claims."""
    artifact.ensure(type(args.max_output_bytes) is int
                    and 0 < args.max_output_bytes <= factory.MAX_FACTORY_OUTPUT,
                    'invalid total output budget')
    artifact.ensure(type(args.reserve_free_bytes) is int and args.reserve_free_bytes >= 0
                    and type(args.reserve_free_inodes) is int and args.reserve_free_inodes >= 0,
                    'invalid management reserve')
    sources = corresponding_sources(lock)
    payload = sum(value['size'] for value in sources.values()) + artifact.MAX_SOURCE
    artifact.ensure(payload <= artifact.MAX_SOURCE_OFFER - 16 * BLOCK,
                    'complete source payload exceeds bound')
    stream = tar_size([*sources.values(), {'size': artifact.MAX_SOURCE}])
    artifact.ensure(stream <= artifact.MAX_SOURCE_OFFER, 'complete source tar stream exceeds bound')
    # Account for DEFLATE expansion as well as tar headers and padding.
    paired = min(artifact.MAX_SOURCE_OFFER, stream + stream // 1000 + BLOCK)
    copies = {'augmented_rootfs': artifact.MAX_ARCHIVE,
              'validation_intake_rootfs': artifact.MAX_ARCHIVE,
              'outer_archive': artifact.MAX_ARCHIVE,
              'paired_source_archive': paired, 'metadata_and_scratch': 64 * BLOCK}
    disk = os.statvfs(root)
    artifact.ensure(disk.f_frsize > 0 and disk.f_bavail >= 0 and disk.f_favail >= 0,
                    'output capacity is unknown')
    required = sum(copies.values()) + 256 * disk.f_frsize
    reserve = max(DISK_RESERVE, args.reserve_free_bytes)
    inode_reserve = max(INODE_RESERVE, args.reserve_free_inodes)
    reasons = []
    if required > args.max_output_bytes:
        reasons.append('output_byte_budget')
    if disk.f_bavail * disk.f_frsize < required + reserve:
        reasons.append('free_disk')
    if disk.f_favail < inode_reserve + 256:
        reasons.append('free_inodes')
    available = memory_available()
    memory = original_size * 2 + 64 * BLOCK
    if available is not None and available < MEMORY_RESERVE + memory:
        reasons.append('available_memory')
    return {'admitted': not reasons, 'reasons': reasons, 'operation': 'ipquality-package',
            'output_parent': str(root), 'device': root.stat().st_dev,
            'block_size': disk.f_frsize, 'max_output_bytes': args.max_output_bytes,
            'reserve_free_bytes': reserve, 'reserve_free_inodes': inode_reserve,
            'required_inodes': 256, 'required_bytes': required, 'copies': copies,
            'observed_free_bytes': disk.f_bavail * disk.f_frsize,
            'observed_free_inodes': disk.f_favail, 'observed_available_memory': available,
            'memory_reserve_bytes': MEMORY_RESERVE, 'memory_working_bytes': memory,
            'source_authenticated': False, 'builder_approved': False, 'full_ready': False}


class Writer:
    def __init__(self, stream, maximum, guard):
        self.stream, self.maximum, self.guard, self.total = stream, maximum, guard, 0

    def write(self, content):
        artifact.ensure(self.total + len(content) <= self.maximum, 'archive byte budget exceeded')
        self.guard.progress()
        self.guard.check(additional_bytes=len(content) + self.guard.plan['block_size'])
        count = self.stream.write(content)
        artifact.ensure(count == len(content), 'short archive write')
        self.total += count
        return count

    def flush(self):
        self.stream.flush()

    def tell(self):
        return self.total


class Reader:
    def __init__(self, stream, expected, guard):
        self.stream, self.expected, self.guard = stream, expected, guard
        self.measured, self.size = hashlib.sha256(), 0

    def read(self, count=-1):
        self.guard.progress()
        content = self.stream.read(min(BLOCK, count) if count >= 0 else BLOCK)
        self.size += len(content)
        self.measured.update(content)
        artifact.ensure(self.size <= self.expected['size'], 'source member grew beyond inventory')
        return content

    def finish(self):
        artifact.ensure(self.size == self.expected['size']
                        and self.measured.hexdigest() == self.expected['sha256'],
                        'source bytes differ from authenticated inventory')


@contextlib.contextmanager
def compressed_tar(path, maximum, guard):
    guard.check(force=True, additional_bytes=guard.plan['block_size'], additional_inodes=1)
    with path.open('xb') as destination:
        os.fchmod(destination.fileno(), 0o644)
        writer = Writer(destination, maximum, guard)
        with gzip.GzipFile(filename='', fileobj=writer, mode='wb', mtime=0, compresslevel=9) as zipped:
            with tarfile.open(fileobj=zipped, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                yield archive
        destination.flush()
        os.fsync(destination.fileno())
    guard.check(force=True)


def pack_files(path, files, maximum, guard, runner=False):
    artifact.ensure(tar_size([{'size': len(content)} for content in files.values()]) <= maximum,
                    'tar payload exceeds explicit expansion bound')
    with compressed_tar(path, maximum, guard) as archive:
        for name, content in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(content), 0o755 if runner and name == artifact.BINARY else 0o644
            reader = Reader(io.BytesIO(content), {'size': len(content), 'sha256': artifact.digest(content)}, guard)
            archive.addfile(member, reader)
            reader.finish()


def source_files(bundle_path, review_path, guard):
    helper = artifact.module('sinan_node_ip_source', artifact.PLUGIN / 'source-helper.py')
    bundle = helper.decode_bundle(read(bundle_path, artifact.MAX_SOURCE, guard))
    original = helper.bundle_files(bundle)
    transformed = helper.transform_files(original)
    sources = {'upstream/' + name: content for name, content in original.items()}
    for directory in (artifact.PLUGIN, artifact.ROOT / 'plugins/nodequality'):
        chosen = list(directory.glob('*.py')) if directory == artifact.PLUGIN else [directory / 'rootfs.py']
        if directory == artifact.PLUGIN:
            chosen.extend(directory.glob('policies/*.py'))
            chosen.append(directory / 'source-lock.json')
        for path in chosen:
            sources[path.relative_to(artifact.ROOT).as_posix()] = read(path, artifact.MAX_RUNNER, guard)
    for name, content in helper.policy_bytes().items():
        sources['plugins/ipquality/policies/' + name + '-policy.py'] = content
    sources['plugins/ipquality/SOURCE.md'] = read(artifact.PLUGIN / 'SOURCE.md', artifact.MAX_RUNNER, guard)
    for name in ('tools/build-ipquality.py', 'tools/ipquality_artifact.py', 'tools/ipquality-rootfs.py',
                 'tools/nodequality-rootfs-build.py', 'tools/nodequality-rootfs-collect.py',
                 'tools/ipquality-inputs.py', 'tools/ipquality-inputs-capacity.py',
                 'tools/ipquality-profile.py', 'LICENSE'):
        sources[name] = read(artifact.ROOT / name, artifact.MAX_SOURCE, guard)
    sources['license-review.json'] = read(review_path, artifact.MAX_SOURCE, guard)
    return sources, transformed


def augment(archive_path, manifest_bytes, transformed, arch, directory, guard):
    helper = artifact.runtime()
    original_deadline = helper._deadline
    def scan_deadline(end):
        guard.progress()
        original_deadline(end)
    helper._deadline = scan_deadline
    manifest = helper.load_manifest(manifest_bytes, arch)
    helper.verify_archive(archive_path, manifest)
    entries = {entry['path']: dict(entry) for entry in manifest['entries']}
    added = {artifact.LIB + name: content for name, content in transformed.items()
             if name in ('patched-ip.sh', 'transport.py', 'ip-iso3166.json', 'ip-dnsbl.list')}
    artifact.ensure(len(added) == 4, 'fixed four-role IPQuality overlay is incomplete')
    added['usr/local/bin/curl'] = b'#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/sinan-ipquality/transport.py "$@"\n'
    for name, content in added.items():
        artifact.ensure(name not in entries, 'factory base contains an uncontrolled script')
        parent = Path(name).parent
        while str(parent) != '.':
            item = entries.get(parent.as_posix())
            artifact.ensure(item is None or item['type'] == 'dir', 'source overlay parent is not ordinary')
            entries.setdefault(parent.as_posix(), {'path': parent.as_posix(), 'type': 'dir', 'mode': 0o755})
            parent = parent.parent
        mode = 0o755 if name in ('usr/local/bin/curl', artifact.LIB + 'patched-ip.sh') else 0o644
        entries[name] = {'path': name, 'type': 'file', 'mode': mode,
                         'sha256': artifact.digest(content), 'size': len(content)}
    rows = sorted(entries.values(), key=lambda item: item['path'])
    expanded = sum(entry.get('size', 0) for entry in rows)
    stream_size = tar_size([{'size': entry.get('size', 0)} for entry in rows])
    artifact.ensure(expanded <= helper.MAX_EXPANDED and stream_size <= helper.MAX_STREAM,
                    'source overlay exceeds rootfs expansion budget')
    output = directory / 'rootfs.tar.gz'
    with helper._ordinary(archive_path, artifact.MAX_ARCHIVE) as (source, _):
        with tarfile.open(fileobj=source, mode='r:gz') as original:
            members = {}
            for member in original:
                guard.progress()
                members[member.name] = member
            with compressed_tar(output, artifact.MAX_ARCHIVE, guard) as archive:
                for entry in rows:
                    guard.progress()
                    member = tarfile.TarInfo(entry['path'])
                    member.mode = entry.get('mode', 0o777)
                    if entry['type'] == 'dir':
                        member.type = tarfile.DIRTYPE
                        archive.addfile(member)
                    elif entry['type'] == 'symlink':
                        member.type, member.linkname = tarfile.SYMTYPE, entry['target']
                        archive.addfile(member)
                    else:
                        member.size = entry['size']
                        body = io.BytesIO(added[entry['path']]) if entry['path'] in added else original.extractfile(members[entry['path']])
                        artifact.ensure(body is not None, 'rootfs member is missing')
                        with body:
                            reader = Reader(body, entry, guard)
                            archive.addfile(member, reader)
                            reader.finish()
    changed = {'schema': 1, 'arch': arch, 'archive': identity(output, artifact.MAX_ARCHIVE, guard),
               'expanded_size': expanded, 'stream_size': stream_size,
               'entries_sha256': artifact.digest(artifact.canonical(rows).rstrip(b'\n')), 'entries': rows}
    changed_bytes = artifact.canonical(changed)
    helper.verify_archive(output, helper.load_manifest(changed_bytes, arch))
    metadata = helper.read_metadata(output, changed, ['usr/share/sinan-rootfs/' + name for name in
                                    ('provenance.json', 'inputs-lock.json', 'source-inventory.json', 'license-inventory.json',
                                     'ipquality-profile.json')] + ['var/lib/dpkg/status'])
    return output, changed_bytes, metadata


def pack_sources(path, mini_source, expected, cache, factory, guard):
    artifact.ensure(tar_size(expected.values()) <= artifact.MAX_SOURCE_OFFER,
                    'paired source tar expansion exceeds bound')
    with compressed_tar(path, artifact.MAX_SOURCE_OFFER, guard) as archive:
        for name, value in sorted(expected.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode = value['size'], 0o644
            if name == 'sinan-source.tar.gz':
                source_context = contextlib.nullcontext((io.BytesIO(mini_source), None))
            else:
                blob = name.removeprefix('debian-sources/')
                ordinary = factory.input_path(cache, blob)
                source_context = artifact.runtime()._ordinary(ordinary, artifact.MAX_SOURCE_OFFER)
            with source_context as (source, metadata):
                artifact.ensure(metadata is None or metadata.st_size == value['size'],
                                'corresponding source length differs from lock')
                reader = Reader(source, value, guard)
                archive.addfile(member, reader)
                reader.finish()
    return identity(path, artifact.MAX_SOURCE_OFFER, guard)


def checksum_inventory(target, guard):
    try:
        data = read(target / 'SHA256SUMS', 4096, guard)
    except FileNotFoundError:
        artifact.ensure(not any(os.path.lexists(target / name) for name in CHECKSUM_NAMES),
                        'existing artifacts have no checksum inventory')
        return {}, None
    values = {}
    for line in data.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([a-z0-9.]+)', line)
        artifact.ensure(match is not None and match[2] in CHECKSUM_NAMES and match[2] not in values,
                        'existing checksum inventory is unsafe')
        values[match[2]] = match[1]
    artifact.ensure(values, 'existing checksum inventory is empty')
    for arch in ('amd64', 'arm64'):
        artifact.ensure((arch in values) == (arch + '.sources.tar.gz' in values),
                        'existing release has no complete corresponding-source pair')
    for name in CHECKSUM_NAMES:
        artifact.ensure(os.path.lexists(target / name) == (name in values),
                        'existing release material is outside the checksum inventory')
        if name in values:
            limit = artifact.MAX_SOURCE_OFFER if name.endswith('.sources.tar.gz') else artifact.MAX_ARCHIVE
            artifact.ensure(identity(target / name, limit, guard)['sha256'] == values[name],
                            'existing release differs from checksum inventory')
    return values, data


def write_control(path, content, guard):
    guard.check(force=True, additional_bytes=len(content) + guard.plan['block_size'], additional_inodes=1)
    with path.open('xb') as output:
        os.fchmod(output.fileno(), 0o644)
        Writer(output, len(content), guard).write(content)
        output.flush()
        os.fsync(output.fileno())


def fsync_directory(path):
    descriptor = artifact.runtime()._directory(str(path))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish(target, arch, outer, paired, hashes, directory, factory, guard):
    """Immutable paired bytes first, checksum inventory second, main marker last.

    Handled failures roll back only this invocation's files. A forced kill cannot
    make multi-file publication transactional; abandoned material is never deleted
    implicitly. The main file is the release publication boundary.
    """
    values, previous = checksum_inventory(target, guard)
    artifact.ensure(arch not in values and not os.path.lexists(target / arch)
                    and not os.path.lexists(target / (arch + '.sources.tar.gz')),
                    'architecture/version already exists; replacement is forbidden')
    values.update({arch: hashes['outer'], arch + '.sources.tar.gz': hashes['paired']})
    content = ''.join(value + '  ' + name + '\n' for name, value in sorted(values.items())).encode()
    staged = directory / 'SHA256SUMS'
    write_control(staged, content, guard)
    backup = directory / 'previous-SHA256SUMS'
    if previous is not None:
        write_control(backup, previous, guard)
    staged_identity = staged.stat().st_dev, staged.stat().st_ino
    target_identity = factory.FactoryCapacity.identity(target)
    created, inventory_installed, completed = [], False, False
    try:
        guard.check(force=True, additional_inodes=3)
        with factory.deferred_signals():
            artifact.ensure(factory.FactoryCapacity.identity(target) == target_identity,
                            'publication directory identity changed')
            destination = target / (arch + '.sources.tar.gz')
            os.link(paired, destination, follow_symlinks=False)
            created.append((destination, paired.stat().st_dev, paired.stat().st_ino))
            paired.unlink()
            os.replace(staged, target / 'SHA256SUMS')
            inventory_installed = True
            fsync_directory(target)
            os.link(outer, target / arch, follow_symlinks=False)
            created.append((target / arch, outer.stat().st_dev, outer.stat().st_ino))
            outer.unlink()
            fsync_directory(target)
        completed = True
    finally:
        if not completed:
            with factory.deferred_signals():
                artifact.ensure(factory.FactoryCapacity.identity(target) == target_identity,
                                'rollback refused changed publication directory')
                for path, device, inode in reversed(created):
                    current = path.lstat()
                    artifact.ensure((current.st_dev, current.st_ino) == (device, inode),
                                    'rollback refused changed publication identity')
                    path.unlink()
                if inventory_installed:
                    current = (target / 'SHA256SUMS').lstat()
                    artifact.ensure((current.st_dev, current.st_ino) == staged_identity,
                                    'rollback refused changed checksum inventory')
                    if previous is None:
                        (target / 'SHA256SUMS').unlink()
                    else:
                        os.replace(backup, target / 'SHA256SUMS')
                fsync_directory(target)
    return target / arch


def build(args):
    factory = artifact.factory()
    artifact.ensure(type(args.deadline_seconds) is int and 0 < args.deadline_seconds <= 7200,
                    'invalid packaging deadline')
    deadline = factory.Deadline(args.deadline_seconds)
    root = private_directory(args.output)
    # A bounded planning preview is never accepted as source authentication.
    lock = artifact.decode(read(args.prepared_directory / 'inputs-lock.json', artifact.MAX_SOURCE))
    factory.validate_lock(lock)
    deadline.check()
    with artifact.runtime()._ordinary((args.rootfs_directory / 'rootfs.tar.gz').absolute(), artifact.MAX_ARCHIVE) as (_, metadata):
        original_size = metadata.st_size
    plan = capacity_plan(factory, root, lock, original_size, args)
    artifact.ensure(plan['admitted'], 'packaging capacity plan rejected: ' + ','.join(plan['reasons']))
    deadline.check()
    target = private_directory(root / 'ipquality' / artifact.VERSION)
    artifact.ensure(target.stat().st_dev == root.stat().st_dev, 'publication crosses a filesystem')
    build_lock = target / '.build.lock'
    owned_lock, directory, capacity = False, None, None
    try:
        with factory.deferred_signals():
            build_lock.mkdir(mode=0o700)
            owned_lock = True
            lock_identity = factory.FactoryCapacity.identity(build_lock)
            directory = Path(tempfile.mkdtemp(prefix='.ipquality-package-', dir=root))
            temporary_identity = (factory.FactoryCapacity.identity(directory), factory.FactoryCapacity.identity(root))
        capacity = factory.FactoryCapacity(directory, plan, deadline)
        guard = Guard(capacity, deadline)
        deadline.capacity = guard
        write_control(directory / 'capacity-plan.json', artifact.canonical(plan), guard)
        # Export verification creates local deadlines; constrain them to this
        # invocation's absolute deadline, owned scratch and dynamic reserves.
        original_deadline = factory.Deadline
        def bounded_deadline(seconds, capacity=None):
            value = original_deadline(seconds, capacity=capacity or guard)
            value.end = min(value.end, deadline.end)
            return value
        factory.Deadline = bounded_deadline
        prepared = factory.verify_prepared(args.prepared_directory, args.approved_builder_image_sha256, _deadline=deadline)
        guard = deadline.capacity
        artifact.ensure(prepared['lock'] == lock and prepared['arch'] == args.arch,
                        'authenticated preparation differs from admitted identity')
        factory.verify_export(args.rootfs_directory, prepared, args.arch)
        sources, transformed = source_files(args.source_bundle, args.license_review, guard)
        manifest = read(args.rootfs_directory / 'rootfs-manifest.json', artifact.MAX_SOURCE, guard)
        rootfs_path, changed, metadata = augment((args.rootfs_directory / 'rootfs.tar.gz').absolute(),
                                                 manifest, transformed, args.arch, directory, guard)
        review = sources['license-review.json']
        review_value = artifact.decode(review)
        artifact.ensure(isinstance(review_value, dict)
                        and all(isinstance(review_value.get(key), str) and review_value[key].strip()
                                for key in ('reviewer', 'evidence')), 'license review declaration is empty')
        artifact.check_license_review(review_value, metadata, artifact.decode(changed))
        for name in ('inputs-lock.json', 'source-inventory.json', 'license-inventory.json', 'ipquality-profile.json'):
            sources['debian/' + name] = metadata['usr/share/sinan-rootfs/' + name]
        mini_path = directory / 'source.tar.gz'
        pack_files(mini_path, sources, artifact.MAX_SOURCE, guard)
        source_archive = read(mini_path, artifact.MAX_SOURCE, guard)
        paired_path = directory / (args.arch + '.sources.tar.gz')
        expected = artifact.source_inventory({'source.tar.gz': source_archive})
        paired_identity = pack_sources(paired_path, source_archive, expected,
                                       Path(prepared['directory']) / 'input-cache', factory, guard)
        rootfs = read(rootfs_path, artifact.MAX_ARCHIVE, guard)
        info = {'schema': 1, 'plugin': 'ipquality', 'version': artifact.VERSION,
                'arch': args.arch, 'profile': 'ipquality-node-v1',
                'source_commit': artifact.SOURCE_COMMIT, 'source_sha256': artifact.SOURCE_SHA256,
                'source_lock_sha256': artifact.digest(sources['plugins/ipquality/source-lock.json']),
                'policy_sha256': artifact.digest(sources['plugins/ipquality/source-policy.py']),
                'transport_sha256': artifact.digest(sources['plugins/ipquality/transport.py']),
                'rootfs_sha256': artifact.digest(rootfs), 'rootfs_manifest_sha256': artifact.digest(changed),
                'license_review_sha256': artifact.digest(review), 'source_archive_sha256': artifact.digest(source_archive),
                'factory_provenance_sha256': artifact.digest(metadata['usr/share/sinan-rootfs/provenance.json'])}
        notice = {'source_offer': {'asset': f'ipquality-{artifact.VERSION}-linux-{args.arch}-sources.tar.gz',
                                   **paired_identity}, 'license': 'AGPL-3.0-only',
                  'notice': 'Fixed xykt/IPQuality source and controlled modifications are included in sinan-source.tar.gz; '
                            'the paired archive includes every authenticated Debian corresponding source byte. '
                            'Copyright inventories and texts remain in the runtime. License-review declarations are '
                            'attestations, not independently verified approval. No commercial hardware tools, report '
                            'upload or host package installation. Source preparation is not node fault-matrix acceptance.'}
        files = {'ipquality': artifact.runner(), 'rootfs.tar.gz': rootfs, 'rootfs-manifest.json': changed,
                 'build-info.json': artifact.canonical(info), 'LICENSE': sources['upstream/LICENSE.ip'],
                 'source.tar.gz': source_archive,
                 'THIRD_PARTY_NOTICES.txt': b'Sinan IPQuality node self-query\n' + artifact.canonical(notice)}
        artifact.validate_files(files, artifact.VERSION, args.arch, intake_parent=directory, progress=guard.progress)
        artifact.validate_source_offer(paired_path, files, artifact.VERSION, args.arch, progress=guard.progress)
        outer = directory / args.arch
        pack_files(outer, files, artifact.MAX_ARCHIVE, guard, runner=True)
        hashes = {'outer': identity(outer, artifact.MAX_ARCHIVE, guard)['sha256'],
                  'paired': paired_identity['sha256']}
        return publish(target, args.arch, outer, paired_path, hashes, directory, factory, guard)
    finally:
        try:
            if directory is not None:
                factory.cleanup_output(directory, guard_mounts=sys.platform == 'linux', capacity=capacity,
                                       expected_identity=temporary_identity)
        finally:
            if owned_lock:
                with factory.deferred_signals():
                    artifact.ensure(factory.FactoryCapacity.identity(build_lock) == lock_identity,
                                    'cleanup refused replaced publication lock')
                    build_lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--source-bundle', type=Path, required=True)
    parser.add_argument('--prepared-directory', type=Path, required=True)
    parser.add_argument('--rootfs-directory', type=Path, required=True)
    parser.add_argument('--approved-builder-image-sha256', required=True)
    parser.add_argument('--license-review', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reserve-free-bytes', type=int, default=DISK_RESERVE)
    parser.add_argument('--reserve-free-inodes', type=int, default=INODE_RESERVE)
    parser.add_argument('--max-output-bytes', type=int, default=4 * 1024 * BLOCK)
    parser.add_argument('--deadline-seconds', type=int, default=1800)
    try:
        with artifact.factory().cli_signals():
            print(build(parser.parse_args()))
    except (ValueError, OSError, tarfile.TarError) as error:
        raise SystemExit('Error: ' + str(error)) from None


if __name__ == '__main__':
    main()
