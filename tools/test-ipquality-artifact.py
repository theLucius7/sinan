#!/usr/bin/env python3
"""Check source-only preparation, inventory and publication guards."""
import gzip
import io
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import ipquality_artifact as artifact


class ArtifactTests(unittest.TestCase):
    def test_signed_inventory_requires_source_license_and_every_auxiliary(self):
        for name in artifact.FILES:
            files = {entry: b'fixture' for entry in artifact.FILES - {name}}
            with self.assertRaisesRegex(ValueError, 'signed inventory'):
                artifact.validate_files(files, artifact.VERSION, 'amd64')

    def test_source_archive_refuses_duplicate_traversal_and_links(self):
        for name, kind in (('../source.py', tarfile.REGTYPE), ('source.py', tarfile.SYMTYPE)):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w:gz', format=tarfile.USTAR_FORMAT) as archive:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = 1 if kind == tarfile.REGTYPE else 0
                member.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                archive.addfile(member, io.BytesIO(b'x') if member.size else None)
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                artifact.unpack(output.getvalue(), maximum=artifact.MAX_SOURCE)
        data = artifact.pack({'source.py': b'print("fixture")\n'})
        self.assertEqual(artifact.unpack(data, maximum=artifact.MAX_SOURCE), {'source.py': b'print("fixture")\n'})

    def test_small_compressed_archive_with_two_gib_limit_uses_bounded_reads(self):
        expected = {'source.py': b'x' * (2 * artifact.READ_CHUNK + 31)}
        data = artifact.pack(expected)
        self.assertLess(len(data), artifact.READ_CHUNK)
        requests = {'gzip': [], 'member': []}
        gzip_read = gzip.GzipFile.read
        member_read = tarfile.ExFileObject.read

        def bounded_read(kind, original):
            def read(source, size=-1):
                self.assertIs(type(size), int)
                self.assertGreater(size, 0)
                self.assertLessEqual(size, artifact.READ_CHUNK)
                requests[kind].append(size)
                return original(source, size)
            return read

        with patch.object(gzip.GzipFile, 'read', bounded_read('gzip', gzip_read)), \
                patch.object(tarfile.ExFileObject, 'read', bounded_read('member', member_read)):
            self.assertEqual(artifact.unpack(data, maximum=artifact.MAX_SOURCE_OFFER), expected)
        self.assertGreater(len(requests['gzip']), 2)
        self.assertGreater(len(requests['member']), 2)

    def test_expansion_limit_allows_exact_size_and_rejects_one_byte_more(self):
        expected = {'source.py': b'print("fixture")\n'}
        data = artifact.pack(expected)
        expanded = len(gzip.decompress(data))
        self.assertLess(len(data), expanded - 1)
        self.assertEqual(artifact.unpack(data, maximum=expanded), expected)
        with self.assertRaisesRegex(ValueError, 'archive expansion exceeds limit'):
            artifact.unpack(data, maximum=expanded - 1)

    def test_unpack_rejects_invalid_limits_before_opening_gzip(self):
        data = artifact.pack({'source.py': b'print("fixture")\n'})
        with patch.object(gzip, 'GzipFile') as reader:
            for maximum in (True, False, 0, -1, 1.5, '2147483648', None):
                with self.subTest(maximum=maximum), \
                        self.assertRaisesRegex(ValueError, 'invalid archive expansion limit'):
                    artifact.unpack(data, maximum=maximum)
            reader.assert_not_called()

    def test_unpack_reads_through_gzip_crc_size_and_complete_trailer(self):
        data = artifact.pack({'source.py': b'print("fixture")\n'})
        corrupt_crc = data[:-8] + bytes([data[-8] ^ 1]) + data[-7:]
        corrupt_size = data[:-4] + bytes([data[-4] ^ 1]) + data[-3:]
        for malformed in (corrupt_crc, corrupt_size, data[:-1], data + b'not a gzip trailer'):
            with self.subTest(trailer=malformed[-8:]), \
                    self.assertRaises((gzip.BadGzipFile, EOFError)):
                artifact.unpack(malformed, maximum=artifact.MAX_SOURCE_OFFER)

    def test_independent_profile_cannot_satisfy_full_hardware_factory(self):
        profile = artifact.module('sinan_ipquality_profile_fixture', artifact.ROOT / 'tools/ipquality-rootfs.py')
        node = profile.factory()
        original = artifact.module('sinan_original_nodequality_factory_fixture', artifact.ROOT / 'tools/nodequality-rootfs-build.py')
        self.assertIn('python3', node.TOOL_PACKAGES)
        self.assertNotIn('fio', node.TOOL_PACKAGES)
        self.assertNotIn('iperf3', node.TOOL_PACKAGES)
        self.assertIn('fio', original.TOOL_PACKAGES)
        self.assertNotEqual(node.PROVENANCE_KIND, original.PROVENANCE_KIND)
        self.assertTrue(original.PENDING)
        self.assertNotEqual(node.PENDING, original.PENDING)
        self.assertIsNone(original.INPUT_PROFILE)
        self.assertIsNotNone(node.INPUT_PROFILE)

    def minimal_metadata(self):
        # Shape/replay admission is exercised by test-ipquality-profile.py.
        # These inert bytes isolate the signed archive/provenance connection.
        prefix = 'usr/share/sinan-rootfs/'
        proof = {'schema': 1, 'scope': 'TEST_ONLY signed metadata propagation',
                 'implementations': {'tools/nodequality-rootfs-build.py': 'a' * 64}}
        content = artifact.canonical(proof)
        lock = {'arch': 'amd64', 'source_epoch': 1, 'builder': {'scope': 'TEST_ONLY'}, 'packages': []}
        sources = {'scope': 'TEST_ONLY inert source inventory'}
        metadata = {prefix + 'ipquality-profile.json': content,
                    prefix + 'inputs-lock.json': artifact.canonical(lock),
                    prefix + 'source-inventory.json': artifact.canonical(sources),
                    prefix + 'license-inventory.json': artifact.canonical({'packages': []}),
                    'var/lib/dpkg/status': b'TEST_ONLY inert status boundary'}
        provenance = {'schema': 1, 'kind': 'sinan-ipquality-debian12-preparation',
            'arch': 'amd64', 'full_ready': False, 'source_authenticated': True,
            'reproducibility_verified': False, 'source_epoch': 1, 'builder': lock['builder'],
            'build_tool_sha256': 'a' * 64, 'pending_capabilities': ['TEST_ONLY'],
            'profile_proof_sha256': artifact.digest(content)}
        for name in ('inputs-lock', 'source-inventory', 'license-inventory'):
            provenance[name.replace('-', '_') + '_sha256'] = artifact.digest(metadata[prefix + name + '.json'])
        metadata[prefix + 'provenance.json'] = artifact.canonical(provenance)
        manifest = {'entries': [{'path': name, 'type': 'file',
                                 'sha256': artifact.digest(value), 'size': len(value)}
                                for name, value in metadata.items()]}
        validator = SimpleNamespace(INPUT_PROFILE=SimpleNamespace(validate_public=lambda value, lock: value),
                                    canonical=lambda value: artifact.canonical(value).rstrip(b'\n'),
                                    PROVENANCE_KIND=provenance['kind'], PENDING=['TEST_ONLY'],
                                    material_inventory=lambda materials: sources,
                                    verify_installed_packages=lambda content, packages, exact_sources: [])
        return metadata, manifest, validator

    def test_minimal_profile_proof_is_mandatory_even_before_license_claim(self):
        with self.assertRaisesRegex(ValueError, 'profile proof is absent'):
            artifact.check_minimal_profile({}, {'entries': []})
        with self.assertRaisesRegex(ValueError, 'profile proof is absent'):
            artifact.check_license_review({'schema': 1, 'reviewed': True}, {}, {'entries': []})

    def test_signed_minimal_profile_bytes_require_both_provenance_and_runtime_binding(self):
        metadata, manifest, validator = self.minimal_metadata()
        with patch.object(artifact, 'factory', return_value=validator):
            self.assertEqual(artifact.check_minimal_profile(metadata, manifest)['schema'], 1)
            for key, value in (('sha256', 'f' * 64), ('size', 0), ('type', 'symlink')):
                changed = {'entries': [dict(manifest['entries'][0], **{key: value}), *manifest['entries'][1:]]}
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'runtime manifest'):
                    artifact.check_minimal_profile(metadata, changed)
            changed = dict(metadata)
            changed['usr/share/sinan-rootfs/provenance.json'] = artifact.canonical({'profile_proof_sha256': 'f' * 64})
            with self.assertRaisesRegex(ValueError, 'factory provenance'):
                artifact.check_minimal_profile(changed, manifest)

    def test_signed_archive_rejects_raw_private_factory_evidence(self):
        metadata, manifest, validator = self.minimal_metadata()
        for private in ('ipquality-profile-private.json', 'input-ledger.json', 'tool-evidence.json',
                        'ipquality-profile-replay-host.json'):
            changed = {'entries': manifest['entries'] + [{'path': 'usr/share/sinan-rootfs/' + private,
                                                         'type': 'file', 'sha256': 'f' * 64, 'size': 1}]}
            with self.subTest(private=private), patch.object(artifact, 'factory', return_value=validator), \
                    self.assertRaisesRegex(ValueError, 'private factory evidence'):
                artifact.check_minimal_profile(metadata, changed)

    def test_packaged_runner_embeds_exact_verifier_and_no_online_bootstrap(self):
        value = artifact.runner()
        self.assertNotIn(b"ROOTFS_SOURCE = '@ROOTFS_HELPER@'", value)
        self.assertIn(b'private mount namespace', value)
        self.assertIn(b'--artifact-sha256', value)
        self.assertNotIn(b'curl -', value)
        self.assertNotIn(b'apt-get', value)

    def test_license_claim_without_inventory_and_evidence_is_refused(self):
        with self.assertRaises((ValueError, KeyError)):
            artifact.check_license_review({'schema': 1, 'reviewed': True}, {}, {'entries': []})

    def test_paired_source_requires_complete_matching_bytes_not_just_urls(self):
        source_files = {'sinan-source.tar.gz': b'inert fixture source', 'debian-sources/test.source': b'complete source fixture'}
        expected = {name: {'size': len(content), 'sha256': artifact.digest(content)} for name, content in source_files.items()}
        data = artifact.pack(source_files)
        offer = {'asset': f'ipquality-{artifact.VERSION}-linux-amd64-sources.tar.gz',
                 'sha256': artifact.digest(data), 'size': len(data)}
        files = {'THIRD_PARTY_NOTICES.txt': b'Sinan IPQuality node self-query\n' + artifact.canonical({
            'source_offer': offer, 'notice': 'TEST_ONLY complete byte-stream fixture; no approved build', 'license': 'AGPL-3.0-only'})}
        with patch.object(artifact, 'source_inventory', return_value=expected):
            artifact.validate_source_offer(data, files, artifact.VERSION, 'amd64')
            for contents in ({'sinan-source.tar.gz': source_files['sinan-source.tar.gz']},
                             {**source_files, 'debian-sources/test.source': b'altered source'},
                             {**source_files, 'unexpected.txt': b'extra'}):
                changed = artifact.pack(contents)
                notice = artifact.decode(files['THIRD_PARTY_NOTICES.txt'].split(b'\n', 1)[1])
                notice['source_offer'].update(size=len(changed), sha256=artifact.digest(changed))
                modified = {'THIRD_PARTY_NOTICES.txt': b'Sinan IPQuality node self-query\n' + artifact.canonical(notice)}
                with self.assertRaises(ValueError):
                    artifact.validate_source_offer(changed, modified, artifact.VERSION, 'amd64')
            with self.assertRaises(ValueError):
                artifact.validate_source_offer(data + b'changed', files, artifact.VERSION, 'amd64')
            trailing = data + gzip.compress(b'unlisted source bytes')
            notice = artifact.decode(files['THIRD_PARTY_NOTICES.txt'].split(b'\n', 1)[1])
            notice['source_offer'].update(size=len(trailing), sha256=artifact.digest(trailing))
            modified = {'THIRD_PARTY_NOTICES.txt': b'Sinan IPQuality node self-query\n' + artifact.canonical(notice)}
            with self.assertRaisesRegex(ValueError, 'unlisted'):
                artifact.validate_source_offer(trailing, modified, artifact.VERSION, 'amd64')

    def test_paired_source_cannot_name_external_or_another_architecture_asset(self):
        for asset_name in ('https://example.invalid/source.tar.gz', '../source.tar.gz',
                           f'ipquality-{artifact.VERSION}-linux-arm64-sources.tar.gz'):
            files = {'THIRD_PARTY_NOTICES.txt': b'Sinan IPQuality node self-query\n' + artifact.canonical({
                'source_offer': {'asset': asset_name, 'size': 1, 'sha256': 'a' * 64},
                'notice': 'TEST_ONLY', 'license': 'AGPL-3.0-only'})}
            with self.assertRaisesRegex(ValueError, 'source-offer descriptor'):
                artifact.source_offer(files, artifact.VERSION, 'amd64')


class ArchiveProfileTests(unittest.TestCase):
    """Real archive reads and exact public inventory checks; no native admission."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sinan-ip-intake-inventory-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.factory = artifact.factory()
        self.profile = artifact.module('ip_intake_profile_tools', artifact.ROOT / 'tools/ipquality-rootfs.py')
        parent_factory = artifact.module('ip_intake_parent_factory', artifact.ROOT / 'tools/nodequality-rootfs-build.py')
        fixtures = artifact.module('ip_intake_material_fixtures', artifact.ROOT / 'tools/test-ipquality-inputs.py')
        parent = fixtures.ParentFixture(self.root / 'TEST_ONLY-parent', parent_factory, self.profile)
        materials = parent.child()
        self.lock = dict(materials, builder={'image_sha256': '1' * 64, 'arch': 'amd64', 'tools': [
            {'name': name, 'path': path, 'version': 'TEST_ONLY never approved', 'sha256': '2' * 64, 'size': 1}
            for name, path in sorted(self.factory.TOOL_PATHS.items())]})
        # This normalized public proof isolates intake. Fresh GPG/APT replay is
        # independently covered by the factory admission fixtures.
        selection = {'schema': 1, 'seeds': sorted(set(self.profile.TOOLS.values()) | {'apt', 'base-files'}),
            'main_essential_names': ['base-files'],
            'package_selection': [{key: value for key, value in row.items() if key != 'blob'}
                                  for row in materials['packages']],
            'installation': False, 'binary_downloads_by_solver': False,
            'network_namespaces': [{'schema': 1, 'operation': operation, 'different_namespace': True,
                                    'interfaces': ['lo'], 'installation': False}
                                   for operation in ('update', 'plan')]}
        profile_contract = artifact.module('ip_intake_profile_contract', artifact.ROOT / 'tools/ipquality-profile.py')
        proof = {'schema': 1, 'kind': profile_contract.KIND, 'profile': profile_contract.PROFILE,
            'arch': 'amd64', 'source_epoch': materials['source_epoch'], 'commands': self.profile.TOOLS,
            'materials': materials, 'materials_sha256': artifact.digest(artifact.canonical(materials)),
            'selection': selection, 'selection_sha256': artifact.digest(artifact.canonical(selection)),
            'parent_materials_sha256': artifact.digest(artifact.canonical(parent.materials)),
            'parent_collection_sha256': artifact.digest((parent.directory / 'collection.json').read_bytes()),
            'derived_selection_sha256': '3' * 64,
            'binding_inputs_lock_sha256': artifact.digest(artifact.canonical(self.lock)),
            'implementations': self.factory.INPUT_PROFILE.code(None),
            **{key: False for key in profile_contract.FALSE_FLAGS}}
        prefix = 'usr/share/sinan-rootfs/'
        installed = [{'name': row['name'], 'version': row['version'], 'architecture': row['architecture']}
                     for row in materials['packages']]
        self.status = ''.join('Package: ' + row['name'] + '\nVersion: ' + row['version']
            + '\nArchitecture: ' + row['architecture'] + '\nStatus: install ok installed\nSource: '
            + row['source_name'] + ' (' + row['source_version'] + ')\n\n'
            for row in materials['packages']).encode()
        self.metadata = {prefix + 'ipquality-profile.json': artifact.canonical(proof),
            prefix + 'inputs-lock.json': artifact.canonical(self.lock),
            prefix + 'source-inventory.json': artifact.canonical(self.factory.material_inventory(materials)),
            prefix + 'license-inventory.json': artifact.canonical({'schema': 1, 'reviewed': False,
                                                                 'packages': sorted(installed, key=lambda row: row['name'])}),
            'var/lib/dpkg/status': self.status}
        self.provenance = {'schema': 1, 'kind': self.factory.PROVENANCE_KIND, 'arch': 'amd64',
            'full_ready': False, 'source_authenticated': True, 'reproducibility_verified': False,
            'source_epoch': materials['source_epoch'], 'builder': self.lock['builder'],
            'build_tool_sha256': proof['implementations']['tools/nodequality-rootfs-build.py'],
            'pending_capabilities': self.factory.PENDING}
        self.archive_fixture = artifact.module('ip_intake_archive_fixtures',
                                                artifact.ROOT / 'tools/test-nodequality-rootfs.py')
        self.counter = 0

    def intake(self, metadata=None, provenance_edits=None, export_check=False):
        metadata = dict(self.metadata if metadata is None else metadata)
        prefix = 'usr/share/sinan-rootfs/'
        provenance = dict(self.provenance,
                          profile_proof_sha256=artifact.digest(metadata[prefix + 'ipquality-profile.json']))
        for name in ('inputs-lock', 'source-inventory', 'license-inventory'):
            provenance[name.replace('-', '_') + '_sha256'] = artifact.digest(metadata[prefix + name + '.json'])
        provenance.update(provenance_edits or {})
        metadata[prefix + 'provenance.json'] = artifact.canonical(provenance)
        directories = set()
        for name in metadata:
            parent = Path(name).parent
            while str(parent) != '.':
                directories.add(parent.as_posix())
                parent = parent.parent
        rows = [{'path': name, 'type': 'dir', 'mode': 0o755} for name in directories]
        rows += [{'path': name, 'type': 'file', 'mode': 0o644, 'size': len(content),
                  'sha256': artifact.digest(content)} for name, content in metadata.items()]
        rows.sort(key=lambda row: row['path'])
        archive, raw = self.archive_fixture.pack(rows, metadata)
        manifest = self.archive_fixture.manifest(rows, archive, len(raw))
        self.counter += 1
        directory = self.root / ('TEST_ONLY-export-' + str(self.counter))
        directory.mkdir(mode=0o700)
        path = directory / 'rootfs.tar.gz'
        path.write_bytes(archive)
        helper = artifact.runtime()
        loaded = helper.load_manifest(artifact.canonical(manifest), 'amd64')
        observed = helper.read_metadata(path, loaded, sorted(metadata))
        if export_check:
            for name, content in metadata.items():
                if name.startswith(prefix):
                    (directory / Path(name).name).write_bytes(content)
            return self.factory.INPUT_PROFILE.verify_export(directory, loaded, {'lock': self.lock},
                                                             self.factory.Deadline(60))
        return artifact.check_minimal_profile(observed, loaded)

    def test_six_real_archive_members_bind_proof_sources_and_actual_installed_status(self):
        proof = self.intake()
        self.assertEqual(proof['materials']['packages'], self.lock['packages'])
        self.assertIs(proof['full_ready'], False)

    def test_export_rechecks_actual_archive_status_before_accepting_sidecar_inventory(self):
        installed = self.intake(export_check=True)
        self.assertEqual(len(installed), len(self.lock['packages']))
        altered = dict(self.metadata, **{'var/lib/dpkg/status': self.status.replace(
            b'Source: fixture-minimal (1.0)', b'Source: fixture-hardware (1.0)', 1)})
        with self.assertRaisesRegex(ValueError, 'corresponding source'):
            self.intake(altered, export_check=True)

    def test_declared_minimal_proof_cannot_replace_missing_actual_package_status(self):
        metadata = dict(self.metadata)
        del metadata['var/lib/dpkg/status']
        with self.assertRaisesRegex(ValueError, 'actual package/source inventory is absent'):
            self.intake(metadata)

    def test_rehashed_archive_cannot_hide_extra_version_source_duplicate_or_uninstalled_records(self):
        first = self.status.split(b'\n\n', 1)[0] + b'\n\n'
        mutations = [self.status + b'Package: fixture-hardware\nVersion: 1.0\nArchitecture: amd64\nStatus: install ok installed\n\n',
            self.status.replace(b'Version: 1.0', b'Version: 2.0', 1),
            self.status.replace(b'Source: fixture-minimal (1.0)', b'Source: fixture-hardware (1.0)', 1),
            self.status + first, self.status.replace(b'Status: install ok installed', b'Status: deinstall ok config-files', 1)]
        for index, status in enumerate(mutations):
            metadata = dict(self.metadata, **{'var/lib/dpkg/status': status})
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.intake(metadata)

    def test_rehashed_source_inventory_and_private_provenance_cannot_pass_exact_binding(self):
        key = 'usr/share/sinan-rootfs/source-inventory.json'
        for field in ('version', 'repository', 'directory'):
            sources = artifact.decode(self.metadata[key])
            sources['sources'][0][field] = 'TEST_ONLY changed source identity'
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'corresponding source inventory'):
                self.intake(dict(self.metadata, **{key: artifact.canonical(sources)}))
        with self.assertRaisesRegex(ValueError, 'exact minimal profile'):
            self.intake(provenance_edits={'cache_directory': str(self.root), 'uid': os.geteuid()})


if __name__ == '__main__':
    unittest.main()
