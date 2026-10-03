"""Validate the complete independently pinned IPQuality artifact before signing."""
import gzip
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'plugins/ipquality'
BINARY = 'ipquality'
VERSION = '87397e2c3196ec796f5477c83343c2354df601ea-node-r1'
SOURCE_COMMIT = '87397e2c3196ec796f5477c83343c2354df601ea'
SOURCE_SHA256 = 'b30df5a3c2204276c54e99dcc5080b46f8a627667730aee7de63b109b8ecaecf'
AUXILIARY = {'rootfs.tar.gz', 'rootfs-manifest.json', 'build-info.json', 'LICENSE',
             'source.tar.gz', 'THIRD_PARTY_NOTICES.txt'}
FILES = AUXILIARY | {BINARY}
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_SOURCE = 8 * 1024 * 1024
MAX_RUNNER = 128 * 1024
MAX_SOURCE_OFFER = 2 * 1024 * 1024 * 1024
READ_CHUNK = 1024 * 1024
LIB = 'usr/local/lib/sinan-ipquality/'


def ensure(condition, message):
    if not condition:
        raise ValueError(message)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def runtime():
    return module('sinan_ipquality_rootfs_runtime', ROOT / 'plugins/nodequality/rootfs.py')


def factory():
    return module('sinan_ipquality_profile', ROOT / 'tools/ipquality-rootfs.py').factory()


def digest(content):
    return hashlib.sha256(content).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'),
                      allow_nan=False).encode() + b'\n'


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        ensure(key not in result, 'duplicate IPQuality JSON key')
        result[key] = value
    return result


def decode(content):
    return json.loads(content, object_pairs_hook=unique_object,
                      parse_constant=lambda _: ensure(False, 'non-finite IPQuality JSON number'))


def runner():
    source = runtime().ordinary(PLUGIN / 'runner.py', MAX_RUNNER)
    verifier = runtime().ordinary(ROOT / 'plugins/nodequality/rootfs.py', MAX_RUNNER)
    anchor = b"ROOTFS_SOURCE = '@ROOTFS_HELPER@'"
    ensure(source.count(anchor) == 1, 'runner verifier marker differs')
    result = source.replace(anchor, b'ROOTFS_SOURCE = ' + repr(verifier.decode()).encode(), 1)
    ensure(len(result) <= MAX_RUNNER, 'IPQuality runner exceeds bound')
    return result


def unpack(data, names=None, maximum=MAX_ARCHIVE):
    ensure(type(maximum) is int and maximum > 0, 'invalid archive expansion limit')
    ensure(isinstance(data, bytes) and 0 < len(data) <= maximum, 'archive size exceeds limit')
    files = {}
    with io.BytesIO() as stream:
        expanded = 0
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
            while content := source.read(min(READ_CHUNK, maximum - expanded + 1)):
                ensure(len(content) <= maximum - expanded, 'archive expansion exceeds limit')
                stream.write(content)
                expanded += len(content)
        # Reading through EOF also verifies gzip CRC and the complete trailer.
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:') as archive:
            for item in archive:
                ensure(item.isfile() and not item.pax_headers and item.name not in files
                       and (names is None or item.name in names) and 0 < item.size <= maximum
                       and item.name.isascii() and not item.name.startswith('/')
                       and all(part not in ('', '.', '..') for part in item.name.split('/')),
                       'unsafe or unexpected IPQuality archive member')
                length = 0
                with archive.extractfile(item) as source, io.BytesIO() as member:
                    while content := source.read(min(READ_CHUNK, item.size - length + 1)):
                        ensure(len(content) <= item.size - length,
                               'IPQuality archive member exceeds declared size')
                        member.write(content)
                        length += len(content)
                    ensure(length == item.size, 'truncated IPQuality archive member')
                    files[item.name] = member.getvalue()
    ensure(names is None or set(files) == names, 'IPQuality archive inventory differs')
    return files


def pack(files):
    ensure(sum(len(content) for content in files.values()) + 10240 <= MAX_ARCHIVE,
           'IPQuality outer stream exceeds limit')
    output = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, content in sorted(files.items()):
                item = tarfile.TarInfo(name)
                item.size, item.mode = len(content), 0o755 if name == BINARY else 0o644
                archive.addfile(item, io.BytesIO(content))
    data = output.getvalue()
    ensure(len(data) <= MAX_ARCHIVE, 'IPQuality compressed archive exceeds limit')
    return data


def archive_files(data):
    return unpack(data, FILES)


def source_offer(files, version, arch):
    ensure(version == VERSION and arch in ('amd64', 'arm64'), 'invalid IPQuality source-offer identity')
    prefix = b'Sinan IPQuality node self-query\n'
    content = files['THIRD_PARTY_NOTICES.txt']
    ensure(content.startswith(prefix) and len(content) <= 16 * 1024, 'source-offer notice is absent or oversized')
    notice = decode(content[len(prefix):])
    ensure(isinstance(notice, dict) and set(notice) == {'source_offer', 'notice', 'license'}
           and notice['license'] == 'AGPL-3.0-only'
           and isinstance(notice['notice'], str) and 0 < len(notice['notice']) <= 4096,
           'source-offer notice fields differ')
    offer = notice['source_offer']
    ensure(isinstance(offer, dict) and set(offer) == {'asset', 'sha256', 'size'}
           and offer['asset'] == f'ipquality-{VERSION}-linux-{arch}-sources.tar.gz'
           and isinstance(offer['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', offer['sha256'])
           and type(offer['size']) is int and 0 < offer['size'] <= MAX_SOURCE_OFFER,
           'signed source-offer descriptor differs')
    return offer


@contextlib.contextmanager
def source_stream(value):
    if isinstance(value, bytes):
        ensure(0 < len(value) <= MAX_SOURCE_OFFER, 'paired source size exceeds bound')
        yield io.BytesIO(value)
    else:
        with runtime()._ordinary(Path(value).absolute(), MAX_SOURCE_OFFER) as (source, _):
            yield source


class LimitedReader:
    def __init__(self, source, maximum):
        self.source, self.maximum, self.total = source, maximum, 0

    def read(self, size=-1):
        maximum = self.maximum - self.total + 1
        content = self.source.read(min(1024 * 1024, maximum) if size < 0 else min(size, maximum))
        self.total += len(content)
        ensure(self.total <= self.maximum, 'paired source decompressed stream exceeds bound')
        return content


def source_inventory(files):
    sources = unpack(files['source.tar.gz'], maximum=MAX_SOURCE)
    lock = decode(sources['debian/inputs-lock.json'])
    factory().validate_lock(lock)
    expected = {'sinan-source.tar.gz': {'size': len(files['source.tar.gz']), 'sha256': digest(files['source.tar.gz'])}}
    for row in lock['sources']:
        for item in row['files']:
            name = 'debian-sources/' + item['blob']
            identity = {key: item[key] for key in ('size', 'sha256')}
            ensure(name not in expected or expected[name] == identity, 'ambiguous corresponding-source blob')
            expected[name] = identity
    ensure(len(expected) <= 16384 and sum(item['size'] for item in expected.values()) <= MAX_SOURCE_OFFER - 16 * 1024 * 1024,
           'complete source offer exceeds its explicit bound')
    return expected


def validate_source_offer(value, files, version, arch, progress=None):
    """Verify the paired published source bytes without retaining archives in memory."""
    offer = source_offer(files, version, arch)
    expected = source_inventory(files)
    def check_progress():
        if progress is not None:
            progress()
    with source_stream(value) as source:
        measured, length = hashlib.sha256(), 0
        while content := source.read(1024 * 1024):
            check_progress()
            measured.update(content)
            length += len(content)
            ensure(length <= offer['size'], 'source offer grew beyond signed length')
        ensure(length == offer['size'] and measured.hexdigest() == offer['sha256'], 'paired source differs from signed declaration')
        source.seek(0)
        seen = set()
        with gzip.GzipFile(fileobj=source) as compressed:
            stream = LimitedReader(compressed, MAX_SOURCE_OFFER)
            with tarfile.open(fileobj=stream, mode='r|') as archive:
                for member in archive:
                    check_progress()
                    ensure(member.name in expected and member.name not in seen and member.isfile()
                           and not member.pax_headers and member.size == expected[member.name]['size']
                           and member.uid == 0 and member.gid == 0, 'paired source has unsafe, duplicate or unexpected members')
                    reader = archive.extractfile(member)
                    measured, length = hashlib.sha256(), 0
                    while content := reader.read(1024 * 1024):
                        check_progress()
                        length += len(content)
                        measured.update(content)
                        ensure(length <= member.size, 'paired source member grew beyond inventory')
                    ensure(length == member.size and measured.hexdigest() == expected[member.name]['sha256'],
                           'complete corresponding source bytes differ from authenticated inventory')
                    seen.add(member.name)
                # Streamed tar reads may have buffered bytes after the first end
                # marker. Validate them before the wrapper discards that buffer.
                ensure(not getattr(archive.fileobj, 'buf', b'').strip(b'\0'),
                       'paired source has unlisted buffered tar content')
            while content := stream.read(1024 * 1024):
                check_progress()
                ensure(not content.strip(b'\0'), 'paired source has unlisted trailing tar content')
        ensure(seen == set(expected), 'paired source offer is incomplete')
    check_progress()


def check_license_review(review, metadata, manifest):
    check_minimal_profile(metadata, manifest)
    licenses = decode(metadata['usr/share/sinan-rootfs/license-inventory.json'])
    sources = decode(metadata['usr/share/sinan-rootfs/source-inventory.json'])
    inputs = decode(metadata['usr/share/sinan-rootfs/inputs-lock.json'])
    ensure(isinstance(review, dict) and set(review) == {'schema', 'profile', 'reviewer', 'evidence',
           'source_commit', 'source_sha256', 'license_inventory_sha256', 'source_inventory_sha256',
           'inputs_lock_sha256', 'packages', 'upstream_license'}, 'invalid IPQuality license review')
    ensure(type(review['schema']) is int and review['schema'] == 1
           and review['profile'] == 'ipquality-node-v1'
           and review['source_commit'] == SOURCE_COMMIT and review['source_sha256'] == SOURCE_SHA256
           and review['upstream_license'] == 'AGPL-3.0-only', 'IPQuality license review identity differs')
    for key in ('reviewer', 'evidence'):
        ensure(isinstance(review[key], str) and 0 < len(review[key]) <= 2048
               and not any(ord(value) < 32 for value in review[key]), 'license review evidence is absent')
    for key in ('license_inventory', 'source_inventory', 'inputs_lock'):
        ensure(review[key + '_sha256'] == digest(metadata['usr/share/sinan-rootfs/' + key.replace('_', '-') + '.json']),
               'license review differs from the actual complete inventory')
    build = factory()
    build.validate_lock(inputs)
    ensure(sources.get('packages') == inputs['packages'], 'source inventory package identity differs')
    ensure(licenses.get('packages') == review['packages'] and isinstance(review['packages'], list)
           and {(row['name'], row['version'], row['architecture']) for row in review['packages']}
           == {(row['name'], row['version'], row['architecture']) for row in inputs['packages']},
           'license review does not cover every installed package')
    paths = {entry['path']: entry for entry in manifest['entries']}
    ensure(isinstance(licenses.get('files'), list) and licenses['files'], 'license text inventory is empty')
    for license_file in licenses['files']:
        entry = paths.get(license_file['path'], {})
        ensure(entry.get('type') == 'file' and entry.get('sha256') == license_file['sha256']
               and entry.get('size') == license_file['size'], 'preserved license text differs')
    profile = module('sinan_ipquality_tools', ROOT / 'tools/ipquality-rootfs.py')
    ensure({item['command'] for item in licenses.get('tools', [])} == set(profile.TOOLS),
           'rootfs contains another diagnostic tool profile')


def check_minimal_profile(metadata, manifest):
    """Require the signed exact selection; host replay remains a factory gate."""
    build = factory()
    prefix = 'usr/share/sinan-rootfs/'
    name = prefix + 'ipquality-profile.json'
    ensure(name in metadata, 'minimal IPQuality profile proof is absent')
    content = metadata[name]
    proof = decode(content)
    inventories = ('inputs-lock.json', 'source-inventory.json', 'license-inventory.json')
    ensure(all(prefix + item in metadata for item in inventories)
           and prefix + 'provenance.json' in metadata and 'var/lib/dpkg/status' in metadata,
           'minimal IPQuality actual package/source inventory is absent')
    lock = decode(metadata[prefix + 'inputs-lock.json'])
    build.INPUT_PROFILE.validate_public(proof, lock)
    ensure(content == build.canonical(proof) + b'\n', 'minimal profile proof bytes are not canonical')
    provenance = decode(metadata[prefix + 'provenance.json'])
    ensure(provenance.get('profile_proof_sha256') == digest(content),
           'factory provenance does not bind the minimal profile')
    expected_provenance = {'schema': 1, 'kind': build.PROVENANCE_KIND, 'arch': lock['arch'],
        'full_ready': False, 'source_authenticated': True, 'reproducibility_verified': False,
        'source_epoch': lock['source_epoch'], 'builder': lock['builder'],
        'inputs_lock_sha256': digest(metadata[prefix + 'inputs-lock.json']),
        'source_inventory_sha256': digest(metadata[prefix + 'source-inventory.json']),
        'license_inventory_sha256': digest(metadata[prefix + 'license-inventory.json']),
        'build_tool_sha256': proof['implementations']['tools/nodequality-rootfs-build.py'],
        'pending_capabilities': build.PENDING, 'profile_proof_sha256': digest(content)}
    ensure(provenance == expected_provenance, 'factory provenance differs from the exact minimal profile')
    ensure(metadata[prefix + 'inputs-lock.json'] == build.canonical(lock) + b'\n',
           'minimal input lock bytes are not canonical')
    sources = build.material_inventory({key: value for key, value in lock.items() if key != 'builder'})
    ensure(metadata[prefix + 'source-inventory.json'] == build.canonical(sources) + b'\n',
           'actual corresponding source inventory differs from the exact minimal closure')
    installed = build.verify_installed_packages(metadata['var/lib/dpkg/status'], lock['packages'],
                                               exact_sources=True)
    licenses = decode(metadata[prefix + 'license-inventory.json'])
    ensure(licenses.get('packages') == installed,
           'actual package status differs from the declared license inventory')
    paths = {entry['path']: entry for entry in manifest['entries']}
    for path in (name, prefix + 'provenance.json', *(prefix + item for item in inventories),
                 'var/lib/dpkg/status'):
        ensure(paths.get(path, {}).get('type') == 'file'
               and paths[path].get('sha256') == digest(metadata[path])
               and paths[path].get('size') == len(metadata[path]),
               'runtime manifest does not bind the minimal profile or actual inventories')
    permitted = {prefix + item for item in ('provenance.json', 'inputs-lock.json', 'source-inventory.json',
                                           'license-inventory.json', 'ipquality-profile.json')}
    ensure(all(path == prefix.rstrip('/') or path in permitted for path in paths if path.startswith(prefix)),
           'runtime provenance contains unreviewed or private factory evidence')
    return proof


def validate_files(files, version, arch, intake_parent=None, progress=None):
    ensure(version == VERSION and arch in ('amd64', 'arm64') and set(files) == FILES,
           'IPQuality version, architecture or signed inventory differs')
    ensure(files[BINARY] == runner(), 'IPQuality executable differs from controlled runner source')
    info = decode(files['build-info.json'])
    fields = {'schema', 'plugin', 'version', 'arch', 'profile', 'source_commit', 'source_sha256',
              'source_lock_sha256', 'policy_sha256', 'transport_sha256', 'rootfs_sha256',
              'rootfs_manifest_sha256', 'license_review_sha256', 'source_archive_sha256',
              'factory_provenance_sha256'}
    ensure(isinstance(info, dict) and set(info) == fields and type(info.get('schema')) is int
           and info.get('schema') == 1 and info.get('plugin') == BINARY
           and info.get('version') == VERSION and info.get('arch') == arch
           and info.get('profile') == 'ipquality-node-v1' and info.get('source_commit') == SOURCE_COMMIT
           and info.get('source_sha256') == SOURCE_SHA256, 'IPQuality build identity differs')
    ensure(all(isinstance(info[key], str) and re.fullmatch(r'[0-9a-f]{64}', info[key])
               for key in fields if key.endswith('_sha256')), 'invalid IPQuality build input digest')
    ensure(info.get('rootfs_sha256') == digest(files['rootfs.tar.gz'])
           and info.get('rootfs_manifest_sha256') == digest(files['rootfs-manifest.json'])
           and info.get('source_archive_sha256') == digest(files['source.tar.gz']),
           'IPQuality build metadata does not bind its inputs')
    helper = runtime()
    if progress is not None:
        original_deadline = helper._deadline
        def checked_deadline(end):
            progress()
            original_deadline(end)
        helper._deadline = checked_deadline
    manifest = helper.load_manifest(files['rootfs-manifest.json'], arch)
    with tempfile.TemporaryDirectory(prefix='sinan-ipquality-intake-', dir=intake_parent) as temporary:
        path = Path(temporary).resolve() / 'rootfs.tar.gz'
        with path.open('xb') as destination:
            content = files['rootfs.tar.gz']
            for offset in range(0, len(content), 1024 * 1024):
                if progress is not None:
                    progress()
                destination.write(content[offset:offset + 1024 * 1024])
        helper.verify_archive(path, manifest)
        names = ['usr/share/sinan-rootfs/' + name for name in
                 ('provenance.json', 'inputs-lock.json', 'source-inventory.json', 'license-inventory.json',
                  'ipquality-profile.json')]
        names.append('var/lib/dpkg/status')
        metadata = helper.read_metadata(path, manifest, names)
    provenance = decode(metadata['usr/share/sinan-rootfs/provenance.json'])
    ensure(provenance.get('kind') == 'sinan-ipquality-debian12-preparation'
           and provenance.get('arch') == arch and provenance.get('source_authenticated') is True
           and provenance.get('full_ready') is False and provenance.get('reproducibility_verified') is False
           and info.get('factory_provenance_sha256') == digest(metadata['usr/share/sinan-rootfs/provenance.json']),
           'rootfs does not identify independent authenticated IPQuality preparation')
    for key in ('inputs_lock', 'source_inventory', 'license_inventory'):
        ensure(provenance.get(key + '_sha256') == digest(metadata['usr/share/sinan-rootfs/' + key.replace('_', '-') + '.json']),
               'factory provenance does not bind its complete inventories')
    check_minimal_profile(metadata, manifest)
    sources = unpack(files['source.tar.gz'], maximum=MAX_SOURCE)
    ensure('license-review.json' in sources and info.get('license_review_sha256') == digest(sources['license-review.json']),
           'actual license review is absent from corresponding source')
    check_license_review(decode(sources['license-review.json']), metadata, manifest)
    ensure(sources.get('plugins/ipquality/runner.py') == runtime().ordinary(PLUGIN / 'runner.py', MAX_RUNNER)
           and sources.get('plugins/nodequality/rootfs.py') == runtime().ordinary(ROOT / 'plugins/nodequality/rootfs.py', MAX_RUNNER),
           'corresponding runner and rootfs-verifier source differs')
    for name in ('plugins/ipquality/source-helper.py', 'plugins/ipquality/SOURCE.md',
                 'tools/build-ipquality.py', 'tools/ipquality_artifact.py', 'tools/ipquality-rootfs.py',
                 'tools/nodequality-rootfs-build.py', 'tools/nodequality-rootfs-collect.py',
                 'tools/ipquality-inputs.py', 'tools/ipquality-inputs-capacity.py',
                 'tools/ipquality-profile.py', 'LICENSE'):
        ensure(sources.get(name) == runtime().ordinary(ROOT / name, MAX_SOURCE),
               'complete corresponding Sinan source differs or is absent: ' + name)
    for name in ('inputs-lock.json', 'source-inventory.json', 'license-inventory.json', 'ipquality-profile.json'):
        ensure(sources.get('debian/' + name) == metadata['usr/share/sinan-rootfs/' + name],
               'corresponding Debian source-offer metadata differs')
    ensure('debian/ipquality-profile-private.json' not in sources
           and not any(name.startswith(('debian/input-ledger', 'debian/tool-evidence',
                                        'debian/ipquality-profile-replay-')) for name in sources),
           'corresponding source contains private factory evidence')
    lock = runtime().ordinary(PLUGIN / 'source-lock.json', MAX_SOURCE)
    ensure(sources.get('plugins/ipquality/source-lock.json') == lock and info.get('source_lock_sha256') == digest(lock),
           'fixed upstream source lock differs')
    source_helper = module('sinan_ipquality_sources', PLUGIN / 'source-helper.py')
    for name, content in source_helper.policy_bytes().items():
        ensure(sources.get('plugins/ipquality/policies/' + name + '-policy.py') == content,
               'corresponding controlled policy source is incomplete')
    source_directory = {Path(name).name: content for name, content in sources.items() if name.startswith('upstream/')}
    # Source helper rechecks the original four bodies and all controlled policy inputs.
    transformed = source_helper.transform_files(source_directory)
    paths = {entry['path']: entry for entry in manifest['entries']}
    for name, content in transformed.items():
        if name not in ('patched-ip.sh', 'transport.py', 'ip-iso3166.json', 'ip-dnsbl.list'):
            continue
        entry = paths.get(LIB + name, {})
        ensure(entry.get('type') == 'file' and entry.get('sha256') == digest(content)
               and entry.get('size') == len(content), 'rootfs script differs from the controlled fixed source')
    shim = b'#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/sinan-ipquality/transport.py "$@"\n'
    ensure(paths.get('usr/local/bin/curl', {}).get('sha256') == digest(shim),
           'rootfs transport wrapper differs from its controlled derivation')
    for key, name in (('policy_sha256', 'source-policy.py'), ('transport_sha256', 'transport.py')):
        content = runtime().ordinary(PLUGIN / name, MAX_SOURCE)
        ensure(info.get(key) == digest(content) and sources.get('plugins/ipquality/' + name) == content,
               'controlled IPQuality policy source differs')
    ensure(files['LICENSE'] == source_directory['LICENSE.ip'], 'fixed upstream license text differs')
    source_offer(files, version, arch)
    source_inventory(files)
    return manifest
