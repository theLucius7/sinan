#!/usr/bin/env python3
"""Owned synthetic preparation/export tests; no downloads or diagnostic execution.

The signature fixture emulates gpgv's machine interface. It does not certify an
actual Debian snapshot, an approved builder image or a reproducible real rootfs.
"""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('nodequality_rootfs_build', REPO / 'tools/nodequality-rootfs-build.py')
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
APPROVED = 'a' * 64


class RootfsBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sinan-rootfs-build-test-')
        self.root = Path(self.temporary.name).resolve()
        self.cache = self.root / 'cache'
        self.cache.mkdir(mode=0o700)
        self.releases = {}
        self.lock = self.make_lock()
        self.lock_path = self.root / 'lock.json'
        self.lock_path.write_bytes(BUILD.canonical(self.lock) + b'\n')
        # This suite tests authentication/export/signals, not host capacity.
        # Keep synthetic operation admission independent of the test machine;
        # the dedicated capacity suite owns low-space/inode boundary evidence.
        observed = types.SimpleNamespace(f_frsize=4096, f_bavail=16 * 1024**3 // 4096,
                                         f_favail=1000000)
        self.capacity_disk = mock.patch.object(BUILD.os, 'statvfs', return_value=observed)
        self.capacity_disk.start()
        self.addCleanup(self.capacity_disk.stop)

    def tearDown(self):
        self.temporary.cleanup()

    def blob(self, name, content):
        path = self.cache / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return {'blob': name, 'sha256': BUILD.digest(content), 'size': len(content)}

    def make_lock(self):
        lock = {'schema': 1, 'arch': 'amd64', 'source_epoch': 1700000000,
                'builder': {'image_sha256': APPROVED, 'arch': 'amd64', 'tools': [
                    {'name': name, 'path': path, 'version': 'fixture-only', 'sha256': 'b' * 64, 'size': 1}
                    for name, path in sorted(BUILD.TOOL_PATHS.items())]},
                'keyring': self.blob('bookworm.gpg', b'owned synthetic keyring'),
                'repositories': [], 'packages': [], 'sources': []}
        source_files = [dict(name='fixture_1.0.dsc', **self.blob('fixture_1.0.dsc', b'owned source descriptor')),
                        dict(name='fixture_1.0.tar.xz', **self.blob('fixture_1.0.tar.xz', b'owned source fixture'))]
        source = {'repository': 'main', 'name': 'fixture', 'version': '1.0', 'directory': 'pool/main/f/fixture', 'files': source_files}
        lock['sources'].append(source)
        binary_records = []
        # The inert export's owned executable/copyright belongs to fixture.
        # Keep it in the signed synthetic closure before the new preflight.
        for index, name in enumerate(sorted(set(BUILD.TOOL_PACKAGES.values()) | {'fixture'})):
            descriptor = self.blob('packages/' + name + '.deb', ('owned ' + name).encode())
            row = {'repository': 'main', 'name': name, 'version': '1.0', 'architecture': 'amd64',
                   'filename': 'pool/main/f/fixture/' + name + '_1.0_amd64.deb', **descriptor,
                   'source_name': 'fixture', 'source_version': '1.0'}
            lock['packages'].append(row)
            binary_records.append('Package: ' + name + '\nVersion: 1.0\nArchitecture: amd64\nSource: fixture (1.0)\n'
                                  + 'Filename: ' + row['filename'] + '\nSHA256: ' + row['sha256']
                                  + '\nSize: ' + str(row['size']) + '\n\n')
        source_record = ('Package: fixture\nVersion: 1.0\nDirectory: pool/main/f/fixture\nChecksums-Sha256:\n'
                         + ''.join(' ' + item['sha256'] + ' ' + str(item['size']) + ' ' + item['name'] + '\n' for item in source_files) + '\n')
        for identity, archive, suite in (('main', 'debian', 'bookworm'), ('security', 'debian-security', 'bookworm-security')):
            indices = []
            for kind, path, content in (('Packages', 'main/binary-amd64/Packages.gz', ''.join(binary_records) if identity == 'main' else ''),
                                        ('Sources', 'main/source/Sources.gz', source_record if identity == 'main' else '')):
                descriptor = self.blob(identity + '-' + kind + '.gz', gzip.compress(content.encode(), mtime=0))
                indices.append(dict(kind=kind, path=path, **descriptor))
            release = ('Origin: Debian\nCodename: ' + suite + '\nSHA256:\n'
                       + ''.join(' ' + item['sha256'] + ' ' + str(item['size']) + ' ' + item['path'] + '\n' for item in indices)).encode()
            inrelease = self.blob(identity + '.InRelease', b'owned synthetic signed envelope: ' + identity.encode())
            self.releases[str(self.cache / inrelease['blob'])] = release
            lock['repositories'].append({'id': identity, 'archive': archive, 'timestamp': '20231115T000000Z',
                                         'suite': suite, 'inrelease': inrelease, 'indices': indices})
        return lock

    def status(self, archive='debian', signer=None, timestamp='1700000000', algorithm='8'):
        signer = signer or sorted(BUILD.SIGNERS[archive])[0]
        return ('[GNUPG:] VALIDSIG ' + signer + ' 2023-11-14 ' + timestamp + ' 0 4 0 1 ' + algorithm + ' 01 ' + signer + '\n').encode()

    def fake_gpgv(self, arguments, deadline, output_limit, stderr=None):
        self.assertEqual(arguments[0], '/usr/bin/gpgv')
        self.assertLessEqual(output_limit, 65536)
        source = Path(arguments[-1])
        identity = source.name.split('.')[0]
        repo = next(item for item in self.lock['repositories'] if item['id'] == identity)
        release = self.releases[str(self.cache / source.name)]
        Path(arguments[arguments.index('--output') + 1]).write_bytes(release)
        return self.status(repo['archive'])

    def prepare_fixture(self):
        with mock.patch.object(BUILD, 'verify_tools'), mock.patch.object(BUILD, 'run_bounded', side_effect=self.fake_gpgv):
            BUILD.prepare(self.lock_path, self.cache, self.root / 'prepared', APPROVED)
            return BUILD.verify_prepared(self.root / 'prepared', APPROVED)

    def inert_tree(self, prepared):
        output = self.root / 'built'
        output.mkdir(mode=0o700)
        tree = output / 'tree'
        tree.mkdir(mode=0o700)
        for directory in ('usr/bin', 'usr/share/doc/fixture', 'var/lib/dpkg'):
            (tree / directory).mkdir(parents=True, mode=0o755)
        (tree / 'usr/bin/bash').write_bytes(b'#!/bin/bash\n# inert owned fixture\n')
        (tree / 'usr/bin/bash').chmod(0o755)
        (tree / 'usr/share/doc/fixture/copyright').write_bytes(b'Owned fixture; no third-party license claim.\n')
        status = b'Package: fixture\nVersion: 1.0\nArchitecture: amd64\nStatus: install ok installed\nSource: fixture (1.0)\n\n'
        (tree / 'var/lib/dpkg/status').write_bytes(status)
        prepared = copy.deepcopy(prepared)
        prepared['lock']['packages'] = [copy.deepcopy(next(row for row in prepared['lock']['packages']
                                                          if row['name'] == 'fixture'))]
        entries = BUILD.tree_entries(tree, BUILD.Deadline(10))
        installed = [{'name': 'fixture', 'version': '1.0', 'architecture': 'amd64'}]
        log = b'owned inert fixture, no actual build\n'
        (output / 'build.log').write_bytes(log)
        receipt = {'schema': 1, 'arch': 'amd64', 'inputs_lock_sha256': prepared['inputs_lock_sha256'],
                   'source_inventory_sha256': prepared['source_inventory_sha256'], 'build_tool_sha256': prepared['build_tool_sha256'],
                   'builder': prepared['lock']['builder'], 'tree_entries_sha256': BUILD.digest(BUILD.canonical(entries)),
                   'installed_packages': installed, 'build_log_sha256': BUILD.digest(log),
                   'full_ready': False, 'reproducibility_verified': False}
        (output / 'build-receipt.json').write_bytes(BUILD.canonical(receipt))
        return tree, prepared

    def export_fixture(self):
        prepared = self.prepare_fixture()
        tree, prepared = self.inert_tree(prepared)
        destination = self.root / 'exported'
        with mock.patch.object(BUILD, 'verify_prepared', return_value=prepared), \
                mock.patch.object(BUILD, 'verify_tools'), \
                mock.patch.object(BUILD, 'TOOL_PACKAGES', {'bash': 'fixture'}):
            receipt = BUILD.export(tree, self.root / 'prepared', destination, APPROVED, 10240)
        return destination, prepared, receipt

    def test_complete_lock_accepts_both_native_architectures(self):
        BUILD.validate_lock(self.lock)
        arm = copy.deepcopy(self.lock)
        arm['arch'] = arm['builder']['arch'] = 'arm64'
        for package in arm['packages']:
            package['architecture'] = 'arm64'
        for repo in arm['repositories']:
            repo['indices'][0]['path'] = 'main/binary-arm64/Packages.gz'
        BUILD.validate_lock(arm)

    def test_default_profile_none_preserves_prepared_and_export_receipt_fields(self):
        self.assertIsNone(BUILD.INPUT_PROFILE)
        directory, prepared, receipt = self.export_fixture()
        self.assertNotIn('profile_proof', prepared)
        self.assertNotIn('profile_proof_sha256', receipt)
        self.assertNotIn('profile_proof_sha256', BUILD.decode(
            (self.root / 'prepared/prepared.json').read_bytes()))
        names = {entry['path'] for entry in BUILD.decode(
            (directory / 'rootfs-manifest.json').read_bytes())['entries']}
        self.assertNotIn(BUILD.META_DIR + '/ipquality-profile.json', names)
        self.assertFalse((directory / 'ipquality-profile.json').exists())
        self.assertEqual(BUILD.verify_export(directory, prepared, 'amd64'), receipt)

    def profiled_export_fixture(self):
        # This isolates generic callback propagation. The separate profile
        # suite exercises real parent authentication and fresh offline replay.
        prepared = self.prepare_fixture()
        tree, prepared = self.inert_tree(prepared)
        proof = {'schema': 1, 'scope': 'TEST_ONLY callback propagation, not profile approval'}
        content = BUILD.canonical(proof) + b'\n'
        prepared.update(profile_proof=proof, profile_proof_bytes=content,
                        profile_proof_sha256=BUILD.digest(content))
        receipt = BUILD.decode((tree.parent / 'build-receipt.json').read_bytes())
        receipt['profile_proof_sha256'] = prepared['profile_proof_sha256']
        (tree.parent / 'build-receipt.json').write_bytes(BUILD.canonical(receipt))
        profile = types.SimpleNamespace(ensure_cleanup_safe=lambda output: None,
                                        validate_public=lambda value, lock, deadline=None: value,
                                        refuse_export=False)
        def inspect_export(directory, manifest, observed_prepared, deadline):
            self.assertEqual(observed_prepared, prepared)
            self.assertIsInstance(deadline, BUILD.Deadline)
            archive_path = Path(directory) / 'rootfs.tar.gz'
            archived = archive_path.read_bytes()
            self.assertEqual(manifest['archive'], {'size': len(archived),
                                                  'sha256': hashlib.sha256(archived).hexdigest()})
            with tarfile.open(archive_path, 'r:gz') as archive:
                self.assertEqual(archive.extractfile(BUILD.META_DIR + '/ipquality-profile.json').read(), content)
                status = archive.extractfile('var/lib/dpkg/status').read()
                self.assertEqual(status, (tree / 'var/lib/dpkg/status').read_bytes())
                self.assertIn(b'Source: fixture (1.0)\n', status)
                self.assertEqual(archive.extractfile(BUILD.META_DIR + '/inputs-lock.json').read(),
                                 (self.root / 'prepared/inputs-lock.json').read_bytes())
                sources = archive.extractfile(BUILD.META_DIR + '/source-inventory.json').read()
                self.assertEqual(json.loads(sources), prepared['source_inventory'])
                self.assertEqual(hashlib.sha256(sources).hexdigest(), prepared['source_inventory_sha256'])
                licenses = json.loads(archive.extractfile(BUILD.META_DIR + '/license-inventory.json').read())
                self.assertEqual(licenses['packages'], [{'name': 'fixture', 'version': '1.0',
                                                        'architecture': 'amd64'}])
            entries = {row['path']: row for row in manifest['entries']}
            self.assertEqual(entries[BUILD.META_DIR + '/ipquality-profile.json']['sha256'],
                             hashlib.sha256(content).hexdigest())
            self.assertEqual(entries['var/lib/dpkg/status']['sha256'], hashlib.sha256(status).hexdigest())
            if profile.refuse_export:
                raise ValueError('TEST_ONLY archive inventory admission refused')
            return licenses['packages']
        profile.verify_export = mock.Mock(side_effect=inspect_export)
        return tree, prepared, profile

    def test_profile_callback_proof_is_carried_into_export_provenance_and_runtime(self):
        tree, prepared, profile = self.profiled_export_fixture()
        destination = self.root / 'profile-export'
        with mock.patch.object(BUILD, 'INPUT_PROFILE', profile), \
                mock.patch.object(BUILD, 'verify_prepared', return_value=prepared), \
                mock.patch.object(BUILD, 'verify_tools'), \
                mock.patch.object(BUILD, 'TOOL_PACKAGES', {'bash': 'fixture'}):
            receipt = BUILD.export(tree, self.root / 'prepared', destination, APPROVED, 10240)
            deadline = BUILD.Deadline(60)
            deadline.capacity = types.SimpleNamespace(check=lambda *args, **kwargs: None)
            self.assertEqual(BUILD.verify_export(destination, prepared, 'amd64', _deadline=deadline), receipt)
            profile.verify_export.assert_called_once()
            profile.refuse_export = True
            with self.assertRaisesRegex(ValueError, 'archive inventory admission refused'):
                BUILD.verify_export(destination, prepared, 'amd64', _deadline=deadline)
            self.assertEqual(profile.verify_export.call_count, 2)
        self.assertEqual(receipt['profile_proof_sha256'], prepared['profile_proof_sha256'])
        self.assertEqual((destination / 'ipquality-profile.json').read_bytes(), prepared['profile_proof_bytes'])
        provenance = BUILD.decode((destination / 'provenance.json').read_bytes())
        self.assertEqual(provenance['profile_proof_sha256'], prepared['profile_proof_sha256'])
        with tarfile.open(destination / 'rootfs.tar.gz', 'r:gz') as archive:
            self.assertEqual(archive.extractfile(BUILD.META_DIR + '/ipquality-profile.json').read(),
                             prepared['profile_proof_bytes'])

    def test_profile_from_another_preparation_rejects_export_and_cleans_owned_output(self):
        tree, prepared, profile = self.profiled_export_fixture()
        receipt = BUILD.decode((tree.parent / 'build-receipt.json').read_bytes())
        receipt['profile_proof_sha256'] = 'f' * 64
        (tree.parent / 'build-receipt.json').write_bytes(BUILD.canonical(receipt))
        destination = self.root / 'rejected-profile-export'
        with mock.patch.object(BUILD, 'INPUT_PROFILE', profile), \
                mock.patch.object(BUILD, 'verify_prepared', return_value=prepared), \
                mock.patch.object(BUILD, 'verify_tools'), \
                mock.patch.object(BUILD, 'TOOL_PACKAGES', {'bash': 'fixture'}), \
                self.assertRaisesRegex(ValueError, 'another minimal input profile'):
            BUILD.export(tree, self.root / 'prepared', destination, APPROVED, 10240)
        self.assertFalse(destination.exists())
        self.assertTrue(tree.is_dir())

    def test_profile_cleanup_callback_blocks_recursive_removal_of_foreign_scratch(self):
        output = self.root / 'owned-output'
        output.mkdir(mode=0o700)
        replacement = output / 'replacement-scratch'
        replacement.mkdir(mode=0o700)
        foreign = replacement / 'preserve.txt'
        foreign.write_bytes(b'foreign replacement must survive')
        profile = types.SimpleNamespace(ensure_cleanup_safe=mock.Mock(
            side_effect=ValueError('cleanup blocked by replaced minimal profile scratch')))
        with mock.patch.object(BUILD, 'INPUT_PROFILE', profile), \
                self.assertRaisesRegex(ValueError, 'replaced minimal profile scratch'):
            BUILD.cleanup_output(output)
        self.assertEqual(foreign.read_bytes(), b'foreign replacement must survive')
        profile.ensure_cleanup_safe.assert_called_once_with(output)

    def test_missing_tool_source_security_or_fixed_input_rejected(self):
        variants = []
        value = copy.deepcopy(self.lock)
        value['packages'].pop()
        variants.append(value)
        value = copy.deepcopy(self.lock)
        value['sources'].clear()
        variants.append(value)
        value = copy.deepcopy(self.lock)
        value['repositories'].pop()
        variants.append(value)
        value = copy.deepcopy(self.lock)
        value['builder']['image_sha256'] = ''
        variants.append(value)
        value = copy.deepcopy(self.lock)
        value['repositories'][0]['indices'][0]['path'] = 'main/binary-arm64/Packages.gz'
        variants.append(value)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                BUILD.validate_lock(value)

    def test_unbound_source_materials_do_not_fabricate_builder_identity(self):
        materials = {key: value for key, value in self.lock.items() if key != 'builder'}
        self.assertEqual(set(BUILD.validate_materials(materials)), {'main', 'security'})
        with self.assertRaisesRegex(ValueError, 'invalid rootfs input lock fields'):
            BUILD.validate_lock(materials)
        with self.assertRaisesRegex(ValueError, 'invalid source material fields'):
            BUILD.validate_materials(self.lock)
        for missing in ('keyring', 'repositories', 'packages', 'sources'):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                BUILD.validate_materials({key: value for key, value in materials.items() if key != missing})

    def test_main_and_security_pool_paths_remain_exactly_scoped(self):
        lock = copy.deepcopy(self.lock)
        lock['packages'][0]['repository'] = 'security'
        lock['packages'][0]['filename'] = 'pool/updates/main/f/fixture/owned.deb'
        BUILD.validate_lock(lock)
        lock['sources'][0]['repository'] = 'security'
        lock['sources'][0]['directory'] = 'pool/updates/main/f/fixture'
        BUILD.validate_lock(lock)
        for archive, path in (('debian', 'pool/updates/main/f/fixture'),
                              ('debian-security', 'pool/main/f/fixture'),
                              ('debian-security', 'pool/updates/non-free/f/fixture'),
                              ('debian', 'pool/contrib/f/fixture')):
            with self.subTest(archive=archive, path=path), self.assertRaises(ValueError):
                BUILD.main_pool_path(archive, path)

    def test_valid_security_pool_path_cannot_bypass_signed_index_identity(self):
        materials = {key: copy.deepcopy(value) for key, value in self.lock.items() if key != 'builder'}
        materials['packages'][0]['repository'] = 'security'
        materials['packages'][0]['filename'] = 'pool/updates/main/f/fixture/owned.deb'
        BUILD.validate_materials(materials)
        with mock.patch.object(BUILD, 'run_bounded', side_effect=self.fake_gpgv), \
                self.assertRaisesRegex(ValueError, 'binary is not covered by signed Packages'):
            BUILD.verify_authenticated_sources(materials, self.cache, BUILD.Deadline(10))

    def test_streamed_gzip_and_xz_records_cross_chunk_boundaries(self):
        description = '界' * 23000
        raw = ('Package: fixture\r\nDescription: ' + description + '\r\n continuation\r\n\r\n'
               'Package: final\nVersion: 1.0').encode('utf-8')
        for suffix, compress in (('.gz', gzip.compress), ('.xz', lzma.compress)):
            with self.subTest(suffix=suffix):
                path = self.root / ('streamed' + suffix)
                path.write_bytes(compress(raw))
                self.assertEqual(list(BUILD.index_records(path, len(raw), BUILD.Deadline(10))), [
                    {'Package': 'fixture', 'Description': description + '\ncontinuation'},
                    {'Package': 'final', 'Version': '1.0'},
                ])
                with self.assertRaisesRegex(ValueError, 'expanded Debian index exceeds its limit'):
                    list(BUILD.index_records(path, len(raw) - 1, BUILD.Deadline(10)))

    def test_streamed_record_budget_and_invalid_fields_rejected(self):
        path = self.root / 'bad.gz'
        path.write_bytes(gzip.compress(b'Package: fixture\nDescription: ' + b'x' * 100 + b'\n\n'))
        with mock.patch.object(BUILD, 'MAX_LOCK', 64), self.assertRaisesRegex(ValueError, 'control record exceeds its limit'):
            list(BUILD.index_records(path, BUILD.MAX_INDEX, BUILD.Deadline(10)))
        for raw in (b'Package: first\nPackage: duplicate\n\n', b' orphan\n\n', b'Package: binary\0\n\n'):
            path.write_bytes(gzip.compress(raw))
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                list(BUILD.index_records(path, BUILD.MAX_INDEX, BUILD.Deadline(10)))

    def test_streamed_index_still_observes_deadline_and_file_kind(self):
        path = self.root / 'deadline.gz'
        path.write_bytes(gzip.compress(b'Package: fixture\n\n'))
        deadline = mock.Mock()
        deadline.check.side_effect = ValueError('owned deadline expired')
        with self.assertRaisesRegex(ValueError, 'owned deadline expired'):
            list(BUILD.index_records(path, BUILD.MAX_INDEX, deadline))
        link = self.root / 'link.gz'
        link.symlink_to(path)
        with self.assertRaises(OSError):
            list(BUILD.index_records(link, BUILD.MAX_INDEX, BUILD.Deadline(10)))

    def test_unbound_authentication_retains_entire_signed_source_chain(self):
        materials = {key: value for key, value in self.lock.items() if key != 'builder'}
        with mock.patch.object(BUILD, 'verify_tools', side_effect=AssertionError('source API must not approve a builder')), \
                mock.patch.object(BUILD, 'run_bounded', side_effect=self.fake_gpgv):
            inventory, signatures = BUILD.verify_authenticated_sources(materials, self.cache, BUILD.Deadline(10))
        self.assertEqual(inventory['packages'], self.lock['packages'])
        self.assertEqual(len(signatures), 2)
        self.assertEqual(len(inventory['sources'][0]['files']), 2)
        source = self.lock['sources'][0]['files'][1]
        (self.cache / source['blob']).write_bytes(b'altered corresponding source')
        with mock.patch.object(BUILD, 'run_bounded', side_effect=self.fake_gpgv), self.assertRaises(ValueError):
            BUILD.verify_authenticated_sources(materials, self.cache, BUILD.Deadline(10))

    def test_prepare_still_requires_approval_before_source_authentication(self):
        with mock.patch.object(BUILD, 'verify_authenticated_sources', side_effect=AssertionError('approval must precede source work')) as authenticated:
            with self.assertRaisesRegex(ValueError, 'builder image was not independently approved'):
                BUILD.verify_inputs(self.lock, self.cache, '0' * 64, BUILD.Deadline(10))
        authenticated.assert_not_called()
        materials = {key: value for key, value in self.lock.items() if key != 'builder'}
        self.lock_path.write_bytes(BUILD.canonical(materials))
        with self.assertRaisesRegex(ValueError, 'invalid rootfs input lock fields'):
            BUILD.prepare(self.lock_path, self.cache, self.root / 'not-prepared', APPROVED)
        self.assertFalse((self.root / 'not-prepared').exists())

    def test_duplicate_json_and_cache_traversal_rejected(self):
        with self.assertRaises(ValueError):
            BUILD.decode(b'{"schema":1,"schema":1}')
        for value in ('../keyring', '/keyring', 'a//b', 'a/./b', 'a\\b'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                BUILD.relative(value)
        (self.cache / 'link').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            BUILD.input_path(self.cache, 'link/lock.json')

    def test_cache_checksum_or_special_file_rejected(self):
        descriptor = self.lock['keyring']
        (self.cache / descriptor['blob']).write_bytes(b'altered input')
        with self.assertRaises(ValueError):
            BUILD.checked_blob(self.cache, descriptor, BUILD.MAX_LOCK, BUILD.Deadline(10))
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            BUILD.read_regular(fifo, 64)

    def test_copy_locked_refuses_fifo_replacement_after_identity_check(self):
        script = '''
import importlib.util, json, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('copy_fifo_build', sys.argv[1])
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
cache, target = Path(sys.argv[2]), Path(sys.argv[3])
value = json.loads(sys.argv[4])
original = build.checked_blob
def replace(cache, value, limit, deadline):
    path = original(cache, value, limit, deadline)
    path.unlink()
    os.mkfifo(path, mode=0o600)
    return path
build.checked_blob = replace
try:
    build.copy_locked(cache, value, target, 8192, build.Deadline(2))
except ValueError:
    assert not target.exists(), 'FIFO was copied or output opened before input validation'
else:
    raise AssertionError('FIFO input was accepted')
'''
        result = subprocess.run([sys.executable, '-c', script,
                                 str(REPO / 'tools/nodequality-rootfs-build.py'), str(self.cache),
                                 str(self.root / 'copy.bin'), json.dumps(self.lock['keyring'])],
                                capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_known_primary_signatures_and_error_states(self):
        for archive in BUILD.SIGNERS:
            self.assertTrue(BUILD.valid_signers(self.status(archive), archive, '20231115T000000Z'))
        for status in (self.status(signer='0' * 40), self.status(timestamp='1900000000'),
                       self.status(algorithm='2'), b'[GNUPG:] BADSIG\n' + self.status(),
                       b'[GNUPG:] EXPKEYSIG\n' + self.status(), b'unstructured verifier output\n'):
            with self.subTest(status=status), self.assertRaises(ValueError):
                BUILD.valid_signers(status, 'debian', '20231115T000000Z')

    def test_explicit_approved_image_cannot_be_self_approved(self):
        for value in ('', '0' * 64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                BUILD.verify_tools(self.lock, value, set())
        BUILD.verify_tools(self.lock, APPROVED, set())

    def test_signed_release_index_and_complete_source_chain(self):
        prepared = self.prepare_fixture()
        self.assertFalse(BUILD.decode((self.root / 'prepared/prepared.json').read_bytes())['full_ready'])
        self.assertEqual(prepared['arch'], 'amd64')
        self.assertEqual(prepared['source_inventory']['sources'][0]['files'][0]['url'],
                         'https://snapshot.debian.org/archive/debian/20231115T000000Z/pool/main/f/fixture/fixture_1.0.dsc')
        self.assertEqual(set(BUILD.TOOL_PACKAGES.values()) | {'fixture'}, {row['name'] for row in prepared['source_inventory']['packages']})

    def test_wrong_signed_release_checksum_cannot_prepare(self):
        key = str(self.cache / 'main.InRelease')
        self.releases[key] = self.releases[key].replace(self.lock['repositories'][0]['indices'][0]['sha256'].encode(), b'0' * 64)
        with mock.patch.object(BUILD, 'verify_tools'), mock.patch.object(BUILD, 'run_bounded', side_effect=self.fake_gpgv), self.assertRaises(ValueError):
            BUILD.prepare(self.lock_path, self.cache, self.root / 'prepared', APPROVED)
        self.assertFalse((self.root / 'prepared').exists())

    def test_derived_mirror_mutation_and_extra_package_rejected(self):
        prepared = self.prepare_fixture()
        directory = Path(prepared['directory'])
        path = directory / 'mirrors/main/bookworm-archive-keyring.gpg'
        original = path.read_bytes()
        path.write_bytes(b'altered mirrored keyring')
        with self.assertRaises(ValueError):
            BUILD.verify_mirrors(directory, self.lock, BUILD.Deadline(10))
        path.write_bytes(original)
        (directory / 'mirrors/main/unlocked.deb').write_bytes(b'owned extraneous fixture')
        with self.assertRaises(ValueError):
            BUILD.verify_mirrors(directory, self.lock, BUILD.Deadline(10))

    def test_native_build_plan_uses_only_offline_mirrors_and_fixed_versions(self):
        prepared = self.prepare_fixture()
        plan = BUILD.build_plan(prepared, self.root / 'new-tree')
        text = '\n'.join(plan)
        self.assertIn('--net', plan)
        self.assertIn('--pid', plan)
        self.assertIn('--kill-child', plan)
        self.assertIn('--mode=root', plan)
        self.assertIn('--format=directory', plan)
        self.assertIn('signed-by=', text)
        self.assertIn('check-valid-until=no', text)
        self.assertIn('file://', text)
        self.assertNotIn('https://', text)
        self.assertNotIn('trusted=yes', text)
        self.assertNotIn('Check-Date', text)
        self.assertNotIn('chrootless', text)
        self.assertIn('bash=1.0', text)
        with self.assertRaises(ValueError):
            BUILD.build_plan(prepared, self.root / 'unsafe tree')

    def test_tree_link_chains_flatten_and_escapes_or_specials_rejected(self):
        tree = self.root / 'links'
        (tree / 'usr/bin').mkdir(parents=True, mode=0o755)
        (tree / 'usr/bin/tool').write_bytes(b'owned executable')
        (tree / 'bin').symlink_to('/usr/bin', target_is_directory=True)
        (tree / 'tool').symlink_to('bin/tool')
        entries = BUILD.tree_entries(tree, BUILD.Deadline(10))
        self.assertEqual(next(row['target'] for row in entries if row['path'] == 'tool'), 'usr/bin/tool')
        (tree / 'escape').symlink_to('../outside')
        with self.assertRaises(ValueError):
            BUILD.tree_entries(tree, BUILD.Deadline(10))
        (tree / 'escape').unlink()
        os.mkfifo(tree / 'fifo')
        with self.assertRaises(ValueError):
            BUILD.tree_entries(tree, BUILD.Deadline(10))

    def test_tree_cycles_preexisting_metadata_and_file_budget_rejected(self):
        tree = self.root / 'bad-tree'
        tree.mkdir(mode=0o700)
        (tree / 'a').symlink_to('b')
        (tree / 'b').symlink_to('a')
        with self.assertRaises(ValueError):
            BUILD.tree_entries(tree, BUILD.Deadline(10))
        (tree / 'a').unlink()
        (tree / 'b').unlink()
        (tree / BUILD.META_DIR).mkdir(parents=True)
        with self.assertRaises(ValueError):
            BUILD.tree_entries(tree, BUILD.Deadline(10))

    def test_export_ustar_manifest_provenance_and_outer_budget(self):
        directory, prepared, receipt = self.export_fixture()
        self.assertEqual(BUILD.verify_export(directory, prepared, 'amd64'), receipt)
        self.assertFalse(receipt['full_ready'])
        self.assertFalse(receipt['reproducibility_verified'])
        manifest = BUILD.decode((directory / 'rootfs-manifest.json').read_bytes())
        raw = gzip.decompress((directory / 'rootfs.tar.gz').read_bytes())
        self.assertEqual(len(raw), manifest['stream_size'])
        self.assertEqual(BUILD.digest(BUILD.canonical(manifest['entries'])), manifest['entries_sha256'])
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                self.assertFalse(member.pax_headers)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertEqual(member.mtime, self.lock['source_epoch'])
                self.assertTrue(member.isfile() or member.isdir() or member.issym())
            embedded = archive.extractfile(BUILD.META_DIR + '/provenance.json').read()
        self.assertEqual(embedded, (directory / 'provenance.json').read_bytes())
        self.assertLessEqual(receipt['archive']['size'] + receipt['manifest']['size'] + receipt['outer_reserve_bytes'], BUILD.MAX_ARCHIVE)

    def test_export_receipt_archive_sidecars_and_manifest_mutations_rejected(self):
        directory, prepared, _ = self.export_fixture()
        for name in ('rootfs.tar.gz', 'rootfs-manifest.json', 'inputs-lock.json', 'source-inventory.json',
                     'license-inventory.json', 'provenance.json'):
            path = directory / name
            original = path.read_bytes()
            path.write_bytes(original + b'owned mutation')
            with self.subTest(name=name), self.assertRaises((ValueError, json.JSONDecodeError)):
                BUILD.verify_export(directory, prepared, 'amd64')
            path.write_bytes(original)
        with self.assertRaises(ValueError):
            BUILD.verify_export(directory, prepared, 'arm64')

    def test_export_matches_independent_runtime_manifest_and_metadata_contract(self):
        directory, _, _ = self.export_fixture()
        spec = importlib.util.spec_from_file_location('nodequality_rootfs_runtime', REPO / 'plugins/nodequality/rootfs.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        manifest = runtime.load_manifest((directory / 'rootfs-manifest.json').read_bytes(), 'amd64')
        runtime.verify_archive(directory / 'rootfs.tar.gz', manifest)
        names = [BUILD.META_DIR + '/' + name for name in
                 ('provenance.json', 'inputs-lock.json', 'source-inventory.json', 'license-inventory.json')]
        metadata = runtime.read_metadata(directory / 'rootfs.tar.gz', manifest, names)
        for name in names:
            self.assertEqual(metadata[name], (directory / Path(name).name).read_bytes())

    def test_export_does_not_claim_license_or_rebuild_completion(self):
        directory, _, _ = self.export_fixture()
        licenses = BUILD.decode((directory / 'license-inventory.json').read_bytes())
        provenance = BUILD.decode((directory / 'provenance.json').read_bytes())
        self.assertFalse(licenses['reviewed'])
        self.assertTrue(licenses['files'])
        self.assertTrue(licenses['tools'])
        self.assertFalse(provenance['full_ready'])
        self.assertFalse(provenance['reproducibility_verified'])
        self.assertTrue(any('geekbench5' in item for item in provenance['pending_capabilities']))
        self.assertTrue(any('nexttrace' in item for item in provenance['pending_capabilities']))

    def test_changed_tree_and_missing_copyright_cannot_export(self):
        prepared = self.prepare_fixture()
        tree, prepared = self.inert_tree(prepared)
        (tree / 'usr/bin/bash').write_bytes(b'changed owned executable')
        with mock.patch.object(BUILD, 'verify_prepared', return_value=prepared), \
                mock.patch.object(BUILD, 'verify_tools'), \
                mock.patch.object(BUILD, 'TOOL_PACKAGES', {'bash': 'fixture'}), self.assertRaises(ValueError):
            BUILD.export(tree, self.root / 'prepared', self.root / 'exported', APPROVED, 10240)
        entries = BUILD.tree_entries(tree, BUILD.Deadline(10))
        (tree / 'usr/share/doc/fixture/copyright').unlink()
        entries = [row for row in entries if not row['path'].endswith('/copyright')]
        with self.assertRaises(ValueError):
            BUILD.license_inventory(tree, entries, [{'name': 'fixture', 'version': '1.0', 'architecture': 'amd64'}])

    def test_checked_reader_rejects_same_size_changed_file(self):
        content = b'owned body'
        entry = {'size': len(content), 'sha256': BUILD.digest(content)}
        reader = BUILD.CheckedReader(io.BytesIO(b'wrong body'), entry, BUILD.Deadline(10))
        reader.read(len(content))
        with self.assertRaises(ValueError):
            reader.finish()

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'waitid') and hasattr(os, 'WNOWAIT'), 'Linux waitid/WNOWAIT child collector required')
    def test_bounded_child_output_and_deadline_reap_owned_producer(self):
        # Runs only tiny owned Python snippets, not gpgv/mmdebstrap/rootfs tools.
        with self.assertRaises(ValueError):
            BUILD.run_bounded([sys.executable, '-c', 'import os; os.write(1, b"x" * 4096)'], BUILD.Deadline(5), 64)
        pidfile = self.root / 'owned-child.pid'
        snippet = 'import os, pathlib, time; pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(os.getpid())); time.sleep(5)'
        with self.assertRaises(ValueError):
            BUILD.run_bounded([sys.executable, '-c', snippet], BUILD.Deadline(0.5), 64)
        self.assertTrue(pidfile.exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)
        with self.assertRaises(ValueError):
            BUILD.run_bounded([sys.executable, '-c', 'raise SystemExit(1)'], BUILD.Deadline(5), 64)

    def test_compressed_index_expansion_is_bounded(self):
        path = self.root / 'owned.gz'
        path.write_bytes(gzip.compress(b'owned ' * 1000, mtime=0))
        with self.assertRaises(ValueError):
            BUILD.expanded_index(path, 64, BUILD.Deadline(10))
        with self.assertRaises(ValueError):
            BUILD.read_regular(self.lock_path, 1)

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'waitid') and hasattr(os, 'WNOWAIT'), 'Linux waitid/WNOWAIT child collector required')
    def test_selector_creation_and_registration_failure_reap_real_child(self):
        real_spawn = subprocess.Popen
        children = []

        def spawn(*args, **kwargs):
            process = real_spawn(*args, **kwargs)
            children.append(process)
            return process

        construction_error = OSError('owned selector construction failure')
        registration_error = OSError('owned selector registration failure')
        selector = mock.Mock()
        selector.register.side_effect = registration_error
        for factory, expected in ((mock.Mock(side_effect=construction_error), construction_error),
                                  (mock.Mock(return_value=selector), registration_error)):
            with self.subTest(stage=str(expected)), mock.patch.object(BUILD.subprocess, 'Popen', side_effect=spawn), \
                    mock.patch.object(BUILD.selectors, 'DefaultSelector', factory):
                with self.assertRaises(OSError) as result:
                    BUILD.run_bounded([sys.executable, '-c', 'import time; time.sleep(30)'], BUILD.Deadline(5), 64)
                self.assertIs(result.exception, expected)
                process = children[-1]
                self.assertIsNotNone(process.returncode)
                self.assertTrue(process.stdout.closed)
                with self.assertRaises(ProcessLookupError):
                    os.kill(process.pid, 0)
        selector.close.assert_called_once()

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'waitid') and hasattr(os, 'WNOWAIT'), 'Linux waitid/WNOWAIT child collector required')
    def test_cleanup_errors_do_not_replace_original_registration_failure(self):
        real_spawn = subprocess.Popen
        children = []

        def spawn(*args, **kwargs):
            process = real_spawn(*args, **kwargs)
            children.append(process)
            return process

        original = OSError('owned registration failure')
        selector = mock.Mock()
        selector.register.side_effect = original
        selector.close.side_effect = OSError('owned selector close failure')
        with mock.patch.object(BUILD.subprocess, 'Popen', side_effect=spawn), \
                mock.patch.object(BUILD.selectors, 'DefaultSelector', return_value=selector):
            with self.assertRaises(OSError) as result:
                BUILD.run_bounded([sys.executable, '-c', 'import time; time.sleep(30)'], BUILD.Deadline(5), 64)
        self.assertIs(result.exception, original)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdout.closed)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)

    def test_unresponsive_child_cleanup_has_a_finite_wait_and_preserves_original(self):
        process, selector = mock.Mock(), mock.Mock()
        process.pid, process.returncode = 123456, None
        original = OSError('owned registration failure')
        selector.register.side_effect = original
        process.wait.side_effect = subprocess.TimeoutExpired(['owned fixture'], BUILD.CHILD_CLEANUP_SECONDS)
        with mock.patch.object(BUILD.os, 'waitid', return_value=None, create=True), \
                mock.patch.object(BUILD.os, 'WNOWAIT', 0, create=True), \
                mock.patch.object(BUILD.os, 'P_PID', 0, create=True), \
                mock.patch.object(BUILD.os, 'WEXITED', 0, create=True), \
                mock.patch.object(BUILD.os, 'WNOHANG', 0, create=True), \
                mock.patch.object(BUILD.subprocess, 'Popen', return_value=process), \
                mock.patch.object(BUILD.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(BUILD.os, 'killpg') as kill:
            with self.assertRaises(OSError) as result:
                BUILD.run_bounded(['owned fixture'], BUILD.Deadline(5), 64)
        self.assertIs(result.exception, original)
        process.wait.assert_called_once_with(timeout=BUILD.CHILD_CLEANUP_SECONDS)
        kill.assert_called_once_with(process.pid, signal.SIGKILL)
        self.assertTrue(any('Child cleanup also failed: TimeoutExpired' in note for note in result.exception.__notes__))

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'waitid') and hasattr(os, 'WNOWAIT'),
                         'Linux owned child-group signal acceptance required')
    def test_cli_term_and_hup_reap_real_owned_child_groups(self):
        # The separate harness adopts/reaps its own grandchild, making the
        # absence assertion independent of the surrounding container's PID 1.
        producer = (
            'import json, os, pathlib, subprocess, sys, time\n'
            'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])\n'
            'ready = pathlib.Path(sys.argv[1]); temporary = pathlib.Path(sys.argv[1] + ".tmp")\n'
            'temporary.write_text(json.dumps({"leader": os.getpid(), "child": child.pid})); os.replace(temporary, ready)\n'
            'time.sleep(30)\n'
        )
        harness = (
            'import ctypes, importlib.util, json, os, pathlib, sys, time\n'
            'if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0: raise OSError("owned subreaper setup failed")\n'
            'spec = importlib.util.spec_from_file_location("owned_builder", sys.argv[1])\n'
            'module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)\n'
            'code = 0\n'
            'try:\n'
            '    with module.cli_signals():\n'
            '        module.run_bounded([sys.executable, "-c", sys.argv[2], sys.argv[3]], module.Deadline(20), 64)\n'
            'except SystemExit as error:\n'
            '    code = error.code\n'
            'finally:\n'
            '    reaped = []\n'
            '    end = time.monotonic() + 5\n'
            '    while time.monotonic() < end:\n'
            '        try: pid, status = os.waitpid(-1, os.WNOHANG)\n'
            '        except ChildProcessError: break\n'
            '        if pid: reaped.append({"pid": pid, "status": status})\n'
            '        else: time.sleep(0.01)\n'
            '    pathlib.Path(sys.argv[4]).write_text(json.dumps({"code": code, "reaped": reaped}))\n'
            'raise SystemExit(code)\n'
        )
        for number in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=number):
                ready = self.root / ('signal-' + str(number) + '.ready')
                receipt = self.root / ('signal-' + str(number) + '.receipt')
                process = subprocess.Popen([sys.executable, '-c', harness, str(REPO / 'tools/nodequality-rootfs-build.py'),
                                            producer, str(ready), str(receipt)], stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, start_new_session=True)
                group = None
                try:
                    end = time.monotonic() + 5
                    while not ready.exists() and time.monotonic() < end and process.poll() is None:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists(), 'owned producer did not reach the signal boundary')
                    group = json.loads(ready.read_text())
                    os.kill(process.pid, number)
                    stdout, stderr = process.communicate(timeout=8)
                    self.assertEqual(stdout, b'')
                    self.assertEqual(stderr, b'')
                    self.assertEqual(process.returncode, 128 + number)
                    result = json.loads(receipt.read_text())
                    self.assertEqual(result['code'], 128 + number)
                    self.assertEqual([row['pid'] for row in result['reaped']], [group['child']])
                    self.assertTrue(os.WIFSIGNALED(result['reaped'][0]['status']))
                    self.assertEqual(os.WTERMSIG(result['reaped'][0]['status']), signal.SIGKILL)
                    for pid in group.values():
                        with self.assertRaises(ProcessLookupError):
                            os.kill(pid, 0)
                finally:
                    if process.poll() is None:
                        os.kill(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
                    # Only a still-live, owned descendant in its recorded group
                    # can authorize this fallback cleanup of a failed fixture.
                    if group is not None:
                        try:
                            if os.getpgid(group['child']) == group['leader']:
                                os.killpg(group['leader'], signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process.stdout.close()
                    process.stderr.close()

    @unittest.skipUnless(hasattr(signal, 'pthread_sigmask'), 'POSIX deferred resource signals required')
    def test_pending_term_after_owned_directory_creation_cleans_prepare_build_export(self):
        prepared = self.prepare_fixture()
        tree, prepared = self.inert_tree(prepared)
        real_reserve, real_read, real_private = BUILD.reserve_output, BUILD.read_regular, BUILD.private_directory
        actual_uid = os.geteuid()

        def reserve_then_signal(path):
            directory = real_reserve(path)
            os.kill(os.getpid(), signal.SIGTERM)
            return directory

        def read(path, *args, **kwargs):
            if str(path) in ('/etc/os-release', '/usr/lib/os-release'):
                return b'ID=debian\nVERSION_ID="12"\n'
            return real_read(path, *args, **kwargs)

        def private(path):
            # Only the native-build admission is mocked as root; the owned
            # test directories must still be checked against their actual UID.
            with mock.patch.object(BUILD.os, 'geteuid', return_value=actual_uid):
                return real_private(path)

        operations = {
            'prepare': lambda output: BUILD.prepare(self.lock_path, self.cache, output, APPROVED),
            'build': lambda output: BUILD.build(self.root / 'prepared', output, APPROVED),
            'export': lambda output: BUILD.export(tree, self.root / 'prepared', output, APPROVED, 10240),
        }
        for name, operation in operations.items():
            output = self.root / ('interrupted-' + name)
            with self.subTest(operation=name), BUILD.cli_signals(), \
                    mock.patch.object(BUILD, 'reserve_output', side_effect=reserve_then_signal), \
                    mock.patch.object(BUILD, 'verify_inputs', return_value=({}, [])), \
                    mock.patch.object(BUILD, 'verify_prepared', return_value=prepared), \
                    mock.patch.object(BUILD, 'verify_tools'), \
                    mock.patch.object(BUILD, 'read_regular', side_effect=read), \
                    mock.patch.object(BUILD, 'private_directory', side_effect=private), \
                    mock.patch.object(BUILD, 'ensure_no_mounts'), \
                    mock.patch.object(BUILD, 'TOOL_PACKAGES', {'bash': 'fixture'}), \
                    mock.patch.object(BUILD.platform, 'machine', return_value='x86_64'), \
                    mock.patch.object(BUILD.sys, 'platform', 'linux'), \
                    mock.patch.object(BUILD.os, 'geteuid', return_value=0):
                with self.assertRaises(SystemExit) as result:
                    operation(output)
                self.assertEqual(result.exception.code, 128 + signal.SIGTERM)
                self.assertFalse(output.exists())

    def test_mount_guard_preserves_failed_output_and_original_error(self):
        output = self.root / 'failed-owned-output'
        output.mkdir(mode=0o700)
        marker = output / 'keep-evidence'
        marker.write_bytes(b'owned failure evidence')
        original = RuntimeError('owned original build failure')
        with mock.patch.object(BUILD, 'ensure_no_mounts', side_effect=ValueError('owned remaining mount')), \
                mock.patch.object(BUILD.shutil, 'rmtree') as remove, mock.patch.object(BUILD.sys, 'stderr', io.StringIO()) as report:
            with self.assertRaises(RuntimeError) as result:
                try:
                    raise original
                finally:
                    BUILD.cleanup_output(output, guard_mounts=True)
        self.assertIs(result.exception, original)
        remove.assert_not_called()
        self.assertTrue(marker.exists())
        self.assertIn('Cleanup failed; owned output retained:', report.getvalue())

    @unittest.skipUnless(sys.platform == 'linux', 'Linux mount inventory required')
    def test_mount_inventory_rejects_escaped_and_nested_mount_paths(self):
        output = self.root / 'owned mount output'
        output.mkdir(mode=0o700)
        canonical = str(output.resolve()).replace(' ', r'\040')
        inventory = ('1 0 0:1 / ' + canonical + '/tree/dev rw - tmpfs tmpfs rw\n').encode()
        with mock.patch.object(BUILD, 'read_regular', return_value=inventory), self.assertRaises(ValueError):
            BUILD.ensure_no_mounts(output)


if __name__ == '__main__':
    unittest.main(verbosity=2)
