#!/usr/bin/env python3
"""Derive an offline IPQuality package profile from authenticated NQ material.

Package/source payload bodies are borrowed read-only, never linked, copied,
downloaded or installed. The solver copies authenticated index/key metadata
into its own budgeted mirrors. Derivation and binding do not approve a builder.
"""
import argparse
import datetime
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PARENT_KIND = 'sinan-nodequality-debian-input-collection'
KIND = 'sinan-ipquality-debian-input-derivation'
PROFILE = 'ipquality-node-v1'
RESERVE = 512 * 1024**2
MEMORY_RESERVE = 256 * 1024**2
INODE_RESERVE = 1024
MAX_LEDGER_FILES = 16384
SNAPSHOT_FIELDS = ('dev', 'ino', 'size', 'sha256', 'mode', 'uid', 'gid',
                   'mtime_ns', 'ctime_ns', 'nlink')
CODE_FILES = ('tools/ipquality-inputs.py', 'tools/ipquality-rootfs.py',
              'tools/ipquality-profile.py',
              'tools/ipquality-inputs-capacity.py', 'tools/nodequality-rootfs-collect.py',
              'tools/nodequality-rootfs-build.py', 'plugins/nodequality/rootfs.py')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def modules():
    import importlib.util
    def load(name, relative):
        spec = importlib.util.spec_from_file_location(name, ROOT / relative)
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value
    profile = load('sinan_ipquality_input_profile', 'tools/ipquality-rootfs.py')
    return {'profile': profile, 'build': profile.factory(), 'collect': profile.collector(),
            'parent_build': load('sinan_nq_parent_authentication', 'tools/nodequality-rootfs-build.py'),
            'capacity': load('sinan_ipquality_input_capacity', 'tools/ipquality-inputs-capacity.py')}


def directory(path):
    """Resolve through ordinary directory descriptors, without following links."""
    path = Path(path).absolute()
    require('..' not in path.parts, 'directory traversal is forbidden')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        value = os.fstat(descriptor)
        require(value.st_uid == os.geteuid() and not value.st_mode & 0o022,
                'input directory must be privately owned')
        return path, {'dev': value.st_dev, 'ino': value.st_ino,
                      'mode': stat.S_IMODE(value.st_mode), 'uid': value.st_uid, 'gid': value.st_gid}
    finally:
        os.close(descriptor)


def snapshot_file(path, limit, deadline):
    path = Path(path).absolute()
    require(type(limit) is int and limit > 0 and '..' not in path.parts,
            'invalid ordinary input bound or path')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.geteuid() and not before.st_mode & 0o022
                and 0 < before.st_size <= limit, 'input must be a bounded ordinary single-link file')
        measured, size = hashlib.sha256(), 0
        while chunk := source.read(65536):
            deadline.check()
            size += len(chunk)
            require(size <= before.st_size, 'input grew during snapshot')
            measured.update(chunk)
        after = os.fstat(source.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_gid',
                  'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        require(size == before.st_size and all(getattr(before, key) == getattr(after, key)
                                              for key in fields), 'input changed during snapshot')
        return {'dev': before.st_dev, 'ino': before.st_ino, 'size': size,
                'sha256': measured.hexdigest(), 'mode': stat.S_IMODE(before.st_mode),
                'uid': before.st_uid, 'gid': before.st_gid, 'mtime_ns': before.st_mtime_ns,
                'ctime_ns': before.st_ctime_ns, 'nlink': before.st_nlink}


def read_snapshot(build, path, limit, deadline):
    identity = snapshot_file(path, limit, deadline)
    content = build.read_regular(path, limit, deadline)
    require(len(content) == identity['size'] and build.digest(content) == identity['sha256'],
            'metadata changed after snapshot')
    require(snapshot_file(path, limit, deadline) == identity, 'metadata identity changed')
    return content, identity


def validate_snapshot(value, build):
    require(isinstance(value, dict) and set(value) == set(SNAPSHOT_FIELDS)
            and all(type(value[key]) is int and value[key] >= 0 for key in SNAPSHOT_FIELDS if key != 'sha256')
            and value['ino'] > 0 and value['size'] > 0 and value['nlink'] == 1
            and value['mode'] <= 0o7777 and isinstance(value['sha256'], str)
            and build.SHA256.fullmatch(value['sha256']), 'invalid ordinary input snapshot')


def strict_subset(parent, child):
    require(isinstance(parent, dict) and isinstance(child, dict)
            and set(parent) == {'schema', 'arch', 'source_epoch', 'keyring', 'repositories', 'packages', 'sources'},
            'invalid profile materials')
    require(set(parent) == set(child), 'derived material fields differ from parent')
    for key in ('schema', 'arch', 'source_epoch', 'keyring', 'repositories'):
        require(child.get(key) == parent.get(key), 'derived profile changed parent source identity')
    for key in ('packages', 'sources'):
        require(isinstance(parent[key], list) and parent[key], 'parent closure is empty')
        require(isinstance(child.get(key), list) and child[key], 'derived profile closure is empty')
        require(len(child[key]) <= len(parent[key]), 'derived profile expanded parent inventory')
        names = set()
        for row in child[key]:
            require(isinstance(row, dict) and row in parent[key], 'derived row is not an exact parent subset')
            name = row.get('name') if key == 'packages' else (row.get('name'), row.get('version'))
            require(name not in names, 'derived profile has duplicate rows')
            names.add(name)
    pairs = {(row['source_name'], row['source_version']) for row in child['packages']}
    require(pairs == {(row['name'], row['version']) for row in child['sources']},
            'derived binary/source closure differs')
    return child


def verify_parent(materials_directory, deadline, loaded=None):
    loaded = loaded or modules()
    build, collect = loaded['parent_build'], loaded['collect']
    parent, parent_identity = directory(materials_directory)
    cache, cache_identity = directory(parent / 'input-cache')
    require(not (parent / 'failure.json').exists(), 'incomplete parent collection cannot be derived')
    metadata, ledger = {}, []
    for name in ('materials.json', 'collection.json', 'request.json', 'keyring-provenance.json',
                 'unbound-inputs.json', 'solver/selection.json', 'capacity-plan.json'):
        raw, identity = read_snapshot(build, parent / name, build.MAX_LOCK, deadline)
        metadata[name] = (build.decode(raw), identity)
        ledger.append({'scope': 'parent', 'path': name, 'identity': identity})
    materials, materials_identity = metadata['materials.json']
    receipt, receipt_identity = metadata['collection.json']
    build.validate_materials(materials)
    require(materials['arch'] == collect.native_arch(), 'parent architecture is not native')
    require(isinstance(receipt, dict) and type(receipt.get('schema')) is int and receipt.get('schema') == 1
            and receipt.get('kind') == PARENT_KIND and receipt.get('complete') is True
            and receipt.get('arch') == materials['arch']
            and receipt.get('source_authenticated') is True
            and receipt.get('materials_sha256') == materials_identity['sha256']
            and receipt.get('builder') is None and receipt.get('lock_ready') is False
            and receipt.get('candidate_builder_image_sha256') is None and receipt.get('inputs_lock_sha256') is None
            and receipt.get('builder_approved') is False
            and receipt.get('runtime_image_identity_verified') is False
            and receipt.get('keyring_acquisition_review_supplied') is True
            and receipt.get('keyring_trust_independently_verified_by_collector') is False
            and receipt.get('reproducibility_verified') is False and receipt.get('full_ready') is False,
            'parent receipt is not the exact complete unbound NQ collection')
    require(metadata['unbound-inputs.json'][0] == {'schema': 1, 'kind': PARENT_KIND,
            'materials_sha256': materials_identity['sha256'], 'builder': None, 'lock_ready': False,
            'builder_approved': False, 'full_ready': False, 'reproducibility_verified': False},
            'parent unbound receipt differs')
    old_solver, solver_identity = metadata['solver/selection.json']
    require(isinstance(old_solver, dict) and type(old_solver.get('schema')) is int and old_solver.get('schema') == 1
            and old_solver.get('installation') is False and old_solver.get('binary_downloads_by_solver') is False
            and receipt.get('solver_selection_sha256') == solver_identity['sha256']
            and old_solver.get('package_selection') == [{key: value for key, value in row.items() if key != 'blob'}
                                                       for row in materials['packages']],
            'parent solver selection identity differs')
    old_capacity, capacity_identity = metadata['capacity-plan.json']
    require(receipt.get('capacity_plan') == {'path': 'capacity-plan.json',
                'sha256': capacity_identity['sha256'], 'size': capacity_identity['size']}
            and isinstance(old_capacity, dict) and type(old_capacity.get('schema')) is int
            and old_capacity.get('schema') == 1
            and old_capacity.get('kind') == PARENT_KIND + '-capacity-plan'
            and old_capacity.get('arch') == materials['arch']
            and old_capacity.get('source_epoch') == materials['source_epoch']
            and old_capacity.get('packages') == materials['packages']
            and old_capacity.get('sources') == materials['sources'],
            'parent capacity inventory identity differs')
    request = metadata['request.json'][0]
    collect.validate_request(request)
    require(request == {key: materials[key] for key in ('schema', 'arch', 'source_epoch')}
            | {'repositories': [{key: repo[key] for key in collect.REPOSITORY_FIELDS}
                                for repo in materials['repositories']]},
            'parent request differs from authenticated material')
    review, review_identity = metadata['keyring-provenance.json']
    require(isinstance(review, dict) and review.get('schema') == 1
            and all(isinstance(review.get(key), str) and 0 < len(review[key]) <= 4096
                    for key in ('source', 'reviewer', 'obtained_at'))
            and {key: review.get(key) for key in ('sha256', 'size')}
                == {key: materials['keyring'][key] for key in ('sha256', 'size')},
            'parent keyring acquisition record differs')
    expected_imports = {repo['archive']: repo['timestamp'] for repo in materials['repositories']}
    imports = receipt.get('imports')
    require(isinstance(imports, list) and len(imports) == len(expected_imports), 'parent imports are incomplete')
    descriptors = {}
    for value, limit in build.all_descriptors(materials):
        previous = descriptors.get(value['blob'])
        require(previous is None or previous[0] == value, 'parent cache descriptor conflict')
        descriptors[value['blob']] = (value, limit)
    seen = set()
    for observed in imports:
        require(isinstance(observed, dict) and observed.get('archive') in expected_imports
                and observed['archive'] not in seen
                and observed.get('selected_timestamp') == expected_imports[observed['archive']],
                'parent import timestamp differs')
        seen.add(observed['archive'])
        value = observed.get('response')
        build.descriptor(value, collect.MAX_IMPORTS)
        previous = descriptors.get(value['blob'])
        require(previous is None or previous[0] == value, 'parent import descriptor conflict')
        descriptors[value['blob']] = (value, collect.MAX_IMPORTS)
    require(len(descriptors) <= MAX_LEDGER_FILES, 'parent input ledger exceeds bound')
    for name, (value, limit) in sorted(descriptors.items()):
        path = build.input_path(cache, name)
        identity = snapshot_file(path, limit, deadline)
        require({key: identity[key] for key in ('sha256', 'size')}
                == {key: value[key] for key in ('sha256', 'size')}, 'parent cache bytes differ')
        ledger.append({'scope': 'cache', 'path': name, 'identity': identity})
    for observed in imports:
        value = observed['response']
        collect.validate_imports(build.read_regular(build.input_path(cache, value['blob']),
                                 collect.MAX_IMPORTS, deadline), observed['archive'], observed['selected_timestamp'])
    inventory, signatures = build.verify_authenticated_sources(materials, cache, deadline)
    require(receipt.get('signatures') == signatures, 'parent recorded signatures differ from actual authentication')
    result = {'directory': parent, 'cache': cache, 'materials': materials, 'receipt': receipt,
              'ledger': {'schema': 1, 'parent_directory': str(parent), 'cache_directory': str(cache),
                         'parent_directory_identity': parent_identity, 'cache_directory_identity': cache_identity,
                         'files': ledger}, 'materials_sha256': materials_identity['sha256'],
              'receipt_sha256': receipt_identity['sha256'], 'keyring_review_sha256': review_identity['sha256'],
              'signatures': signatures, 'inventory': inventory}
    verify_ledger(result['ledger'], deadline, build)
    return result


def verify_ledger(ledger, deadline, build):
    require(isinstance(ledger, dict) and set(ledger) == {'schema', 'parent_directory', 'cache_directory',
            'parent_directory_identity', 'cache_directory_identity', 'files'}
            and type(ledger['schema']) is int and ledger['schema'] == 1,
            'invalid borrowed input ledger')
    parent, parent_identity = directory(ledger['parent_directory'])
    cache, cache_identity = directory(ledger['cache_directory'])
    require(cache == parent / 'input-cache' and parent_identity == ledger['parent_directory_identity']
            and cache_identity == ledger['cache_directory_identity'], 'borrowed directory identity changed')
    require(isinstance(ledger['files'], list) and 0 < len(ledger['files']) <= MAX_LEDGER_FILES + 7,
            'invalid borrowed ledger size')
    seen = set()
    for row in ledger['files']:
        require(isinstance(row, dict) and set(row) == {'scope', 'path', 'identity'}
                and row['scope'] in ('parent', 'cache') and isinstance(row['identity'], dict)
                and set(row['identity']) == set(SNAPSHOT_FIELDS), 'invalid borrowed ledger entry')
        validate_snapshot(row['identity'], build)
        build.relative(row['path'])
        key = row['scope'], row['path']
        require(key not in seen, 'duplicate borrowed ledger entry')
        seen.add(key)
        path = build.input_path(parent if row['scope'] == 'parent' else cache, row['path'])
        require(snapshot_file(path, max(1, row['identity']['size']), deadline) == row['identity'],
                'borrowed input identity changed')


class BorrowingCollector:
    """Only new output is owned; registered parent bodies remain external."""
    def __init__(self, output, cache, arch, deadline, guard):
        self.output, self.cache, self.arch = output, cache, arch
        self.deadline, self.guard = deadline, guard

    def budget(self, additional=0):
        self.guard.check(force=True, additional_bytes=additional)

    def obtain(self, *args, **kwargs):
        raise ValueError('offline derivation never obtains network payloads')


class Guard:
    def __init__(self, capacity, helper):
        self.capacity, self.helper, self.output = capacity, helper, capacity.output
        self.last_memory = None
        self.next_memory = 0
        self.oom_baseline = None

    def __getattr__(self, name):
        return getattr(self.capacity, name)

    @property
    def last(self):
        return {'resources': self.capacity.last, 'memory_observation': self.last_memory,
                'oom_counter_baseline': self.oom_baseline}

    def check(self, force=False, additional_bytes=0, additional_inodes=0):
        result = self.capacity.check(force, additional_bytes, additional_inodes)
        if force or time.monotonic() >= self.next_memory:
            self.last_memory = self.helper.available_memory()
            require(type(self.last_memory.get('available_bytes')) is int
                    and self.last_memory['available_bytes'] >= MEMORY_RESERVE,
                    'host MemAvailable is below the 256 MiB management floor')
            observations = self.last_memory.get('cgroup_observations')
            require(self.last_memory.get('cgroup_v2_observed') is True
                    and isinstance(observations, list) and observations,
                    'cgroup-v2 memory.events observations are unknown')
            events = {}
            for row in observations:
                require(isinstance(row, dict) and isinstance(row.get('path'), str)
                        and row['path'] not in events and isinstance(row.get('memory_events'), dict),
                        'cgroup memory.events observation is missing')
                require(all(type(row['memory_events'].get(key)) is int
                            and row['memory_events'][key] >= 0 for key in ('oom', 'oom_kill')),
                        'cgroup OOM counters are unknown')
                events[row['path']] = {key: row['memory_events'][key] for key in ('oom', 'oom_kill')}
            if self.oom_baseline is None:
                self.oom_baseline = events
            else:
                require(set(events) == set(self.oom_baseline), 'cgroup observation membership changed')
                require(all(events[path][key] == old[key] for path, old in self.oom_baseline.items()
                            for key in ('oom', 'oom_kill')), 'cgroup OOM counter changed during derivation')
            self.next_memory = time.monotonic() + 0.25
        return result

    def write(self, path, content, mode=0o600):
        self.check(force=True, additional_bytes=len(content) + self.plan['block_size'], additional_inodes=1)
        self.capacity.write(path, content, mode)
        self.check(force=True)

    def finish(self):
        self.check(force=True)
        self.write(self.output / 'memory-observation.json', self.helper.BUILD.canonical({
            'schema': 1, 'memory_floor_bytes': MEMORY_RESERVE, 'observation': self.last_memory,
            'oom_counter_baseline': self.oom_baseline, 'reclaim_is_guaranteed': False}) + b'\n')
        self.capacity.finish()
        self.check(force=True)


def output_plan(build, parent, max_output_bytes, reserve_free_bytes):
    parent, _ = directory(parent)
    require(type(max_output_bytes) is int and 0 < max_output_bytes <= build.MAX_FACTORY_OUTPUT,
            'invalid new output byte budget')
    require(type(reserve_free_bytes) is int and RESERVE <= reserve_free_bytes <= build.MAX_FACTORY_OUTPUT,
            'at least 512 MiB management space must be retained')
    disk = os.statvfs(parent)
    require(disk.f_frsize > 0 and disk.f_bavail >= 0 and disk.f_favail >= 0,
            'output filesystem capacity is unknown')
    reasons = []
    if disk.f_bavail * disk.f_frsize < reserve_free_bytes:
        reasons.append('free_disk')
    if disk.f_favail < INODE_RESERVE + 64:
        reasons.append('free_inodes')
    return {'schema': 1, 'kind': KIND + '-capacity', 'operation': 'derive-or-bind',
            'output_parent': str(parent), 'device': parent.stat().st_dev, 'block_size': disk.f_frsize,
            'admitted': not reasons, 'reasons': reasons, 'max_output_bytes': max_output_bytes,
            'reserve_free_bytes': reserve_free_bytes, 'reserve_free_inodes': INODE_RESERVE,
            'required_inodes': 64, 'borrowed_new_allocated_bytes': 0, 'hard_quota': False}


def code_ledger(build, deadline):
    return [{'path': name, 'identity': snapshot_file(ROOT / name, build.MAX_LOCK, deadline)}
            for name in CODE_FILES]


def verify_code(ledger, build, deadline):
    require(isinstance(ledger, list) and [row.get('path') for row in ledger] == list(CODE_FILES),
            'derivation code inventory differs')
    for row in ledger:
        require(isinstance(row, dict) and set(row) == {'path', 'identity'}, 'invalid code snapshot')
        validate_snapshot(row['identity'], build)
        require(snapshot_file(ROOT / row['path'], build.MAX_LOCK, deadline) == row['identity'],
                'derivation implementation changed')


def collect_tools(collect, build, deadline):
    evidence = collect.record_collection_tools(deadline)
    snapshots = []
    for item in evidence['executables']:
        snapshots.append({'path': item['resolved_path'],
                          'identity': snapshot_file(item['resolved_path'], build.MAX_ARCHIVE, deadline)})
    return {'schema': 1, 'observation': evidence, 'snapshots': snapshots,
            'builder_approved': False, 'runtime_image_identity_verified': False}


def verify_tools(evidence, build, deadline):
    require(isinstance(evidence, dict) and set(evidence) == {'schema', 'observation', 'snapshots',
            'builder_approved', 'runtime_image_identity_verified'}
            and type(evidence['schema']) is int and evidence['schema'] == 1
            and evidence['builder_approved'] is False and evidence['runtime_image_identity_verified'] is False,
            'invalid actual tool evidence')
    require(isinstance(evidence['snapshots'], list) and evidence['snapshots'], 'actual tool snapshot is absent')
    observations = evidence['observation'].get('executables') if isinstance(evidence['observation'], dict) else None
    require(isinstance(observations, list) and observations
            and all(isinstance(row, dict) and isinstance(row.get('resolved_path'), str) for row in observations),
            'actual executable observations are absent')
    expected = {row['resolved_path']: {key: row[key] for key in ('sha256', 'size')} for row in observations}
    require(len(expected) == len(observations), 'duplicate executable observations')
    paths = set()
    for row in evidence['snapshots']:
        require(isinstance(row, dict) and set(row) == {'path', 'identity'}
                and row['path'] not in paths, 'duplicate or invalid tool snapshot')
        paths.add(row['path'])
        validate_snapshot(row['identity'], build)
        require(row['path'] in expected and {key: row['identity'][key] for key in ('sha256', 'size')}
                == expected[row['path']], 'tool snapshot differs from observed executable')
        require(snapshot_file(row['path'], build.MAX_ARCHIVE, deadline) == row['identity'],
                'derivation tool bytes or identity changed')
    require(paths == set(expected), 'tool snapshot omitted an executable')


def save(build, guard, name, value):
    content = build.canonical(value) + b'\n'
    require(len(content) <= build.MAX_LOCK, 'derived metadata exceeds bounded reader')
    guard.write(guard.output / name, content, 0o600)
    return build.digest(content)


def select(parent, output, deadline, guard, loaded):
    build, collect, helper = loaded['build'], loaded['collect'], loaded['capacity']
    bounds = helper.authenticated_expansion(parent['materials'], parent['cache'], deadline)
    collector = BorrowingCollector(output, parent['cache'], parent['materials']['arch'], deadline, guard)
    indices = {repo['id']: {item['kind']: build.input_path(parent['cache'], item['blob'])
                           for item in repo['indices']} for repo in parent['materials']['repositories']}
    packages, solver = collect.solve(collector, parent['materials']['repositories'], indices,
        build.input_path(parent['cache'], parent['materials']['keyring']['blob']), authenticated_expansion=bounds)
    sources = collect.source_closure(packages, parent['materials']['repositories'], indices, deadline)
    selected = dict(parent['materials'], packages=[dict(row, blob=row['sha256'] + '.deb') for row in packages],
                    sources=[dict(row, files=[dict(item, blob=item['sha256'] + '.source') for item in row['files']])
                             for row in sources])
    strict_subset(parent['materials'], selected)
    build.validate_materials(selected)
    build.verify_authenticated_sources(selected, parent['cache'], deadline)
    return selected, solver, bounds


def finish_failure(build, output, identity, guard, evidence, failure, operation):
    if identity is None:
        if failure is not None and hasattr(failure, 'add_note'):
            failure.add_note('Created output ownership was not confirmed; directory retained')
        removed = False
    else:
        removed = build.cleanup_output(output, guard_mounts=True, capacity=guard, expected_identity=identity)
    if evidence is None and removed and failure is not None:
        evidence = build.preserve_factory_failure(output, operation, failure, guard)
    build.record_factory_cleanup(evidence, removed, failure)


def derive(materials_directory, output_path, max_output_bytes, seconds, reserve_free_bytes=RESERVE):
    loaded = modules()
    build, collect = loaded['build'], loaded['collect']
    require(type(seconds) is int and 0 < seconds <= collect.MAX_SECONDS, 'invalid derivation deadline')
    collect.native_arch()
    deadline = build.Deadline(seconds)
    parent_path, _ = directory(materials_directory)
    requested_output = Path(output_path).absolute()
    require('..' not in requested_output.parts and not requested_output.is_relative_to(parent_path)
            and not parent_path.is_relative_to(requested_output), 'derived output must be disjoint from parent material')
    plan = output_plan(build, requested_output.parent, max_output_bytes, reserve_free_bytes)
    output, complete, guard, parent, evidence, failure, identity = None, False, None, None, None, None, None
    try:
        with build.deferred_signals():
            output = build.reserve_output(output_path)
            identity = build.FactoryCapacity.identity(output), build.FactoryCapacity.identity(output.parent)
            guard = Guard(build.FactoryCapacity(output, plan, deadline), loaded['capacity'])
        deadline.capacity = guard
        guard.check(force=True)
        save(build, guard, 'capacity-plan.json', plan)
        code, tools = code_ledger(build, deadline), collect_tools(collect, build, deadline)
        parent = verify_parent(materials_directory, deadline, loaded)
        require(not output.is_relative_to(parent['directory']) and not parent['directory'].is_relative_to(output),
                'derived output must be disjoint from parent material')
        selected, solver, bounds = select(parent, output, deadline, guard, loaded)
        profile = {'schema': 1, 'id': PROFILE, 'commands': loaded['profile'].TOOLS}
        hashes = {name: save(build, guard, name, value) for name, value in (
            ('materials.json', selected), ('profile.json', profile), ('input-ledger.json', parent['ledger']),
            ('code-ledger.json', code), ('tool-evidence.json', tools), ('expanded-indices.json', bounds))}
        solver_hash = snapshot_file(output / 'solver/selection.json', build.MAX_LOCK, deadline)['sha256']
        descriptors = {value['blob']: value['size'] for value, _ in build.all_descriptors(selected)}
        verify_ledger(parent['ledger'], deadline, build)
        verify_code(code, build, deadline)
        verify_tools(tools, build, deadline)
        receipt = {'schema': 1, 'kind': KIND, 'profile': PROFILE, 'arch': selected['arch'],
            'created_at': collect.timestamp(), 'parent': {'kind': PARENT_KIND, 'directory': str(parent['directory']),
                'materials_sha256': parent['materials_sha256'], 'collection_sha256': parent['receipt_sha256'],
                'keyring_review_sha256': parent['keyring_review_sha256']}, 'cache_directory': str(parent['cache']),
            'files_sha256': hashes, 'solver_selection_sha256': solver_hash,
            'borrowed_logical_bytes': sum(row['identity']['size'] for row in parent['ledger']['files']
                                          if row['scope'] == 'cache'),
            'selected_logical_bytes': sum(descriptors.values()), 'borrowed_new_allocated_bytes': 0,
            'source_authenticated': True, 'keyring_review_supplied': True,
            'keyring_trust_independently_verified': False, 'builder': None, 'lock_ready': False,
            'builder_approved': False, 'runtime_image_identity_verified': False,
            'reproducibility_verified': False, 'full_ready': False, 'installation': False,
            'network_requests': False, 'payload_downloads': False,
            'memory_observation': guard.last_memory}
        save(build, guard, 'derivation.json', receipt)
        verify_ledger(parent['ledger'], deadline, build)
        verify_code(code, build, deadline)
        verify_tools(tools, build, deadline)
        guard.finish()
        complete = True
        return receipt
    except BaseException as error:
        failure = error
        if output is not None:
            evidence = build.preserve_factory_failure(output, 'ipquality-derive', error, guard)
        raise
    finally:
        if not complete and output is not None:
            finish_failure(build, output, identity, guard, evidence, failure, 'ipquality-derive')


def verify_derivation(directory_path, deadline, loaded=None):
    loaded = loaded or modules()
    build = loaded['build']
    derived, directory_identity = directory(directory_path)
    raw, receipt_identity = read_snapshot(build, derived / 'derivation.json', build.MAX_LOCK, deadline)
    sidecars = {'derivation.json': receipt_identity}
    receipt = build.decode(raw)
    required = {'schema', 'kind', 'profile', 'arch', 'created_at', 'parent', 'cache_directory', 'files_sha256',
        'solver_selection_sha256', 'borrowed_logical_bytes', 'selected_logical_bytes',
        'borrowed_new_allocated_bytes', 'source_authenticated',
        'keyring_review_supplied', 'keyring_trust_independently_verified', 'builder', 'lock_ready',
        'builder_approved', 'runtime_image_identity_verified', 'reproducibility_verified', 'full_ready',
        'installation', 'network_requests', 'payload_downloads', 'memory_observation'}
    require(isinstance(receipt, dict) and set(receipt) == required
            and type(receipt['schema']) is int and receipt['schema'] == 1
            and receipt['kind'] == KIND and receipt['profile'] == PROFILE
            and receipt['source_authenticated'] is True and receipt['keyring_review_supplied'] is True
            and receipt['builder'] is None and type(receipt['borrowed_new_allocated_bytes']) is int
            and receipt['borrowed_new_allocated_bytes'] == 0,
            'invalid derived receipt identity')
    require(isinstance(receipt['created_at'], str), 'derived timestamp is absent')
    try:
        created = datetime.datetime.fromisoformat(receipt['created_at'])
    except ValueError as error:
        raise ValueError('invalid derived timestamp') from error
    require(created.utcoffset() == datetime.timedelta(0), 'derived timestamp must be UTC')
    for key in ('keyring_trust_independently_verified', 'lock_ready', 'builder_approved',
                'runtime_image_identity_verified', 'reproducibility_verified', 'full_ready',
                'installation', 'network_requests', 'payload_downloads'):
        require(receipt[key] is False, 'derived profile claims unsupported approval or execution')
    require(isinstance(receipt['parent'], dict) and set(receipt['parent']) == {'kind', 'directory',
            'materials_sha256', 'collection_sha256', 'keyring_review_sha256'}
            and receipt['parent']['kind'] == PARENT_KIND, 'invalid derivation parent binding')
    parent = verify_parent(receipt['parent']['directory'], deadline, loaded)
    require(receipt['parent'] == {'kind': PARENT_KIND, 'directory': str(parent['directory']),
            'materials_sha256': parent['materials_sha256'], 'collection_sha256': parent['receipt_sha256'],
            'keyring_review_sha256': parent['keyring_review_sha256']}
            and receipt['arch'] == parent['materials']['arch']
            and receipt['cache_directory'] == str(parent['cache']), 'derived profile parent identity changed')
    names = {'materials.json', 'profile.json', 'input-ledger.json', 'code-ledger.json',
             'tool-evidence.json', 'expanded-indices.json'}
    require(isinstance(receipt['files_sha256'], dict) and set(receipt['files_sha256']) == names,
            'derived metadata inventory differs')
    require(all(isinstance(value, str) and build.SHA256.fullmatch(value)
                for value in receipt['files_sha256'].values()), 'invalid derived metadata checksum')
    values = {}
    for name in sorted(names):
        content, identity = read_snapshot(build, derived / name, build.MAX_LOCK, deadline)
        require(identity['sha256'] == receipt['files_sha256'][name], 'derived sidecar bytes differ')
        sidecars[name] = identity
        values[name] = build.decode(content)
    require(values['profile.json'] == {'schema': 1, 'id': PROFILE, 'commands': loaded['profile'].TOOLS},
            'derived tool profile differs')
    require(values['input-ledger.json'] == parent['ledger'], 'derived input ledger is stale or incomplete')
    loaded['capacity'].expansion_budget(parent['materials']['repositories'], values['expanded-indices.json'])
    require(values['expanded-indices.json'] == loaded['capacity'].authenticated_expansion(
            parent['materials'], parent['cache'], deadline), 'derived signed expansion identity changed')
    verify_code(values['code-ledger.json'], build, deadline)
    verify_tools(values['tool-evidence.json'], build, deadline)
    child = values['materials.json']
    strict_subset(parent['materials'], child)
    build.validate_materials(child)
    build.verify_authenticated_sources(child, parent['cache'], deadline)
    solver, solver_identity = read_snapshot(build, derived / 'solver/selection.json', build.MAX_LOCK, deadline)
    sidecars['solver/selection.json'] = solver_identity
    require(solver_identity['sha256'] == receipt['solver_selection_sha256'], 'derived solver evidence differs')
    parsed = build.decode(solver)
    require(isinstance(parsed, dict) and parsed.get('installation') is False
            and parsed.get('binary_downloads_by_solver') is False,
            'derived solver claims installation or downloads')
    indices = {repo['id']: {item['kind']: build.input_path(parent['cache'], item['blob'])
                           for item in repo['indices']} for repo in parent['materials']['repositories']}
    seeds, essentials = loaded['collect'].essential_seeds(parent['materials']['repositories'], indices, deadline)
    require(type(parsed.get('schema')) is int and parsed.get('schema') == 1 and parsed.get('seeds') == seeds
            and parsed.get('main_essential_names') == essentials
            and parsed.get('package_selection') == [{key: value for key, value in row.items() if key != 'blob'}
                                                   for row in child['packages']], 'derived solver profile differs')
    namespaces = parsed.get('network_namespaces')
    require(isinstance(namespaces, list) and len(namespaces) == 2
            and all(isinstance(row, dict) and row.get('different_namespace') is True
                    and row.get('interfaces') == ['lo'] and row.get('installation') is False
                    for row in namespaces)
            and [row.get('operation') for row in namespaces] == ['update', 'plan'],
            'derived solver namespace evidence differs')
    descriptors = {value['blob']: value['size'] for value, _ in build.all_descriptors(child)}
    require(type(receipt['selected_logical_bytes']) is int
            and receipt['selected_logical_bytes'] == sum(descriptors.values())
            and type(receipt['borrowed_logical_bytes']) is int
            and receipt['borrowed_logical_bytes'] == sum(row['identity']['size']
                for row in parent['ledger']['files'] if row['scope'] == 'cache'), 'borrowed logical size differs')
    require(not os.path.lexists(derived / 'input-cache') and not os.path.lexists(derived / 'collection.json'),
            'derived input must not impersonate a cache or HTTP collection')
    verify_ledger(parent['ledger'], deadline, build)
    return {'directory': derived, 'directory_identity': directory_identity,
            'parent': parent, 'child': child, 'receipt': receipt, 'sidecars': sidecars,
            'ledger': values['input-ledger.json'], 'code': values['code-ledger.json'],
            'tools': values['tool-evidence.json'], 'derivation_sha256': build.digest(raw)}


def bind(derived_directory, candidate_path, output_path, seconds,
         max_output_bytes=256 * 1024**2, reserve_free_bytes=RESERVE):
    loaded = modules()
    build, collect = loaded['build'], loaded['collect']
    require(type(seconds) is int and 0 < seconds <= collect.MAX_SECONDS, 'invalid binding deadline')
    collect.native_arch()
    deadline = build.Deadline(seconds)
    derived_path, _ = directory(derived_directory)
    requested_output = Path(output_path).absolute()
    require('..' not in requested_output.parts and not requested_output.is_relative_to(derived_path)
            and not derived_path.is_relative_to(requested_output), 'binding output must be disjoint from derived input')
    # Read only the parent path for preflight overlap rejection. Full receipt,
    # source and ledger authentication still occurs after guarded admission.
    preflight = build.decode(build.read_regular(derived_path / 'derivation.json', build.MAX_LOCK, deadline))
    require(isinstance(preflight, dict) and isinstance(preflight.get('parent'), dict)
            and isinstance(preflight['parent'].get('directory'), str), 'binding parent path is absent')
    parent_path, _ = directory(preflight['parent']['directory'])
    require(not requested_output.is_relative_to(parent_path) and not parent_path.is_relative_to(requested_output),
            'binding output must be disjoint from parent material')
    plan = output_plan(build, requested_output.parent, max_output_bytes, reserve_free_bytes)
    output, complete, guard, evidence, failure, identity = None, False, None, None, None, None
    try:
        with build.deferred_signals():
            output = build.reserve_output(output_path)
            identity = build.FactoryCapacity.identity(output), build.FactoryCapacity.identity(output.parent)
            guard = Guard(build.FactoryCapacity(output, plan, deadline), loaded['capacity'])
        deadline.capacity = guard
        guard.check(force=True)
        save(build, guard, 'capacity-plan.json', plan)
        verified = verify_derivation(derived_directory, deadline, loaded)
        require(not output.is_relative_to(verified['parent']['directory'])
                and not output.is_relative_to(verified['directory']), 'binding output overlaps input directories')
        selected, _, bounds = select(verified['parent'], output, deadline, guard, loaded)
        require(selected == verified['child'], 'binding replay changed the minimal selected profile')
        current_tools = collect_tools(collect, build, deadline)
        verify_tools(current_tools, build, deadline)
        save(build, guard, 'tool-evidence.json', current_tools)
        candidate_bytes, candidate_identity = read_snapshot(build, Path(candidate_path), build.MAX_LOCK, deadline)
        candidate = collect.verify_candidate(build.decode(candidate_bytes), selected['arch'], deadline)
        lock = dict(selected, builder=candidate)
        build.validate_lock(lock)
        lock_sha = save(build, guard, 'inputs-lock.json', lock)
        guard.write(output / 'candidate-builder.json', candidate_bytes, 0o600)
        save(build, guard, 'expanded-indices.json', bounds)
        verify_ledger(verified['ledger'], deadline, build)
        verify_code(verified['code'], build, deadline)
        verify_tools(verified['tools'], build, deadline)
        require(directory(verified['directory'])[1] == verified['directory_identity'],
                'derived input directory changed during binding')
        for name, previous in verified['sidecars'].items():
            require(snapshot_file(verified['directory'] / name, build.MAX_LOCK, deadline) == previous,
                    'derived input sidecar changed during binding')
        require(snapshot_file(candidate_path, build.MAX_LOCK, deadline) == candidate_identity,
                'candidate changed during binding')
        receipt = {'schema': 1, 'kind': KIND + '-binding', 'profile': PROFILE, 'arch': selected['arch'],
            'derivation_directory': str(verified['directory']), 'derivation_sha256': verified['derivation_sha256'],
            'materials_sha256': verified['receipt']['files_sha256']['materials.json'],
            'inputs_lock_sha256': lock_sha, 'cache_directory': str(verified['parent']['cache']),
            'parent_collection_sha256': verified['parent']['receipt_sha256'],
            'lock_ready': True, 'builder_approved': False, 'runtime_image_identity_verified': False,
            'reproducibility_verified': False, 'full_ready': False,
            'installation': False, 'network_requests': False, 'payload_downloads': False}
        save(build, guard, 'binding.json', receipt)
        guard.finish()
        complete = True
        return receipt
    except BaseException as error:
        failure = error
        if output is not None:
            evidence = build.preserve_factory_failure(output, 'ipquality-derived-bind', error, guard)
        raise
    finally:
        if not complete and output is not None:
            finish_failure(build, output, identity, guard, evidence, failure, 'ipquality-derived-bind')


def main():
    loaded = modules()
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_subparsers(dest='operation', required=True)
    derivation = operations.add_parser('derive')
    derivation.add_argument('--materials', type=Path, required=True)
    binding = operations.add_parser('bind')
    binding.add_argument('--derived-inputs', type=Path, required=True)
    binding.add_argument('--candidate-builder', type=Path, required=True)
    for operation in (derivation, binding):
        operation.add_argument('--output', type=Path, required=True)
        operation.add_argument('--max-output-bytes', type=int, required=operation is derivation,
                               default=256 * 1024**2)
        operation.add_argument('--timeout-seconds', type=int, required=True)
        operation.add_argument('--reserve-free-bytes', type=int, default=RESERVE)
    args = parser.parse_args()
    with loaded['build'].cli_signals():
        result = derive(args.materials, args.output, args.max_output_bytes, args.timeout_seconds,
                        args.reserve_free_bytes) if args.operation == 'derive' else bind(
            args.derived_inputs, args.candidate_builder, args.output, args.timeout_seconds,
            args.max_output_bytes, args.reserve_free_bytes)
    print(loaded['build'].canonical(result).decode('ascii'))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('IPQuality derivation error: ' + str(error)) from None
