#!/usr/bin/env python3
"""Exercise the local rootfs contract with small inert archives, never tools."""
import copy
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import signal
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'plugins/nodequality/rootfs.py'
SPEC = importlib.util.spec_from_file_location('nodequality_rootfs', SCRIPT)
rootfs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rootfs)
INERT = b'#!/bin/sh\nprintf SHOULD_NEVER_EXECUTE\n'


def canonical(rows):
    return json.dumps(rows, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')


def inventory():
    return [
        {'path': 'bin', 'type': 'symlink', 'target': 'usr/bin'},
        {'path': 'empty', 'type': 'file', 'mode': 0o600, 'size': 0,
         'sha256': hashlib.sha256(b'').hexdigest()},
        {'path': 'usr', 'type': 'dir', 'mode': 0o755},
        {'path': 'usr/bin', 'type': 'dir', 'mode': 0o755},
        {'path': 'usr/bin/probe', 'type': 'file', 'mode': 0o755, 'size': len(INERT),
         'sha256': hashlib.sha256(INERT).hexdigest()},
        {'path': 'usr/bin/sh', 'type': 'symlink', 'target': 'probe'},
    ]


def pack(rows, contents=None, extras=(), omitted=(), duplicate=False):
    contents = {'empty': b'', 'usr/bin/probe': INERT, **(contents or {})}
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for row in reversed(rows):
            if row['path'] in omitted:
                continue
            info = tarfile.TarInfo(row['path'])
            info.uid = info.gid = info.mtime = 0
            if row['type'] == 'file':
                payload = contents[row['path']]
                info.size, info.mode = len(payload), row['mode']
                archive.addfile(info, io.BytesIO(payload))
                if duplicate and row['path'] == 'usr/bin/probe':
                    archive.addfile(info, io.BytesIO(payload))
            elif row['type'] == 'dir':
                info.type, info.mode = tarfile.DIRTYPE, row['mode']
                archive.addfile(info)
            else:
                info.type, info.mode, info.linkname = tarfile.SYMTYPE, 0o777, row['target']
                archive.addfile(info)
        for info, payload in extras:
            archive.addfile(info, io.BytesIO(payload))
    raw = output.getvalue()
    return gzip.compress(raw, mtime=0), raw


def manifest(rows, compressed, stream_size):
    return {'schema': 1, 'arch': 'amd64',
            'archive': {'size': len(compressed), 'sha256': hashlib.sha256(compressed).hexdigest()},
            'expanded_size': sum(row.get('size', 0) for row in rows),
            'stream_size': stream_size, 'entries': rows,
            'entries_sha256': hashlib.sha256(canonical(rows)).hexdigest()}


class Fixture:
    def __init__(self, directory, rows=None, **options):
        self.directory = Path(directory).resolve()
        self.rows = inventory() if rows is None else rows
        self.compressed, self.raw = pack(self.rows, **options)
        self.archive = self.directory / 'rootfs.tar.gz'
        self.control = self.directory / 'rootfs-manifest.json'
        self.workspace = self.directory / 'workspace'
        self.workspace.mkdir(mode=0o700)
        self.value = manifest(self.rows, self.compressed, len(self.raw))
        self.write()

    def write(self):
        self.archive.write_bytes(self.compressed)
        self.control.write_bytes(json.dumps(self.value).encode())

    def altered_archive(self, raw):
        self.raw = raw
        self.compressed = gzip.compress(raw, mtime=0)
        self.value['archive'] = {'size': len(self.compressed),
                                 'sha256': hashlib.sha256(self.compressed).hexdigest()}
        self.write()

    def loaded(self):
        return rootfs.load_manifest(rootfs.ordinary(self.control, rootfs.MAX_MANIFEST), 'amd64')

    def verify(self):
        return rootfs.verify_archive(self.archive, self.loaded())

    def extract(self):
        return rootfs.extract(self.archive, self.loaded(), self.workspace, 'amd64')


class ManifestTests(unittest.TestCase):
    def test_valid_manifest_and_full_stream_verification_do_not_materialize_or_execute(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            before = set(fixture.directory.iterdir())
            receipt = fixture.verify()
            self.assertEqual(receipt['archive_sha256'], fixture.value['archive']['sha256'])
            self.assertEqual(receipt['entries_sha256'], fixture.value['entries_sha256'])
            self.assertEqual((receipt['files'], receipt['dirs'], receipt['symlinks']), (2, 2, 2))
            self.assertEqual(set(fixture.directory.iterdir()), before)
            self.assertEqual(list(fixture.workspace.iterdir()), [])
            self.assertNotIn('full_ready', receipt)
            self.assertNotIn('signed', receipt)

    def test_duplicate_keys_unknown_fields_types_architecture_and_inventory_digest_reject(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            payload = json.dumps(fixture.value).encode()
            with self.assertRaises(ValueError):
                rootfs.load_manifest(b'{"schema":1,"schema":1,' + payload[1:], 'amd64')
            edits = [lambda value: value.update(unknown=True),
                     lambda value: value.update(schema=True),
                     lambda value: value.update(arch='arm64'),
                     lambda value: value['archive'].update(size=True),
                     lambda value: value.update(expanded_size=True),
                     lambda value: value.update(entries_sha256='0' * 64),
                     lambda value: value.update(entries=list(reversed(value['entries'])))]
            for edit in edits:
                value = copy.deepcopy(fixture.value)
                edit(value)
                with self.subTest(edit=edit), self.assertRaises(ValueError):
                    rootfs.load_manifest(json.dumps(value).encode(), 'amd64')

    def test_manifest_bounds_are_independent_of_compression_ratio(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            for field, limit in [('expanded_size', rootfs.MAX_EXPANDED),
                                 ('stream_size', rootfs.MAX_STREAM)]:
                value = copy.deepcopy(fixture.value)
                value[field] = limit + 512
                with self.subTest(field=field), self.assertRaises(ValueError):
                    rootfs.load_manifest(json.dumps(value).encode(), 'amd64')
            value = copy.deepcopy(fixture.value)
            value['archive']['size'] = rootfs.MAX_COMPRESSED + 1
            with self.assertRaises(ValueError):
                rootfs.load_manifest(json.dumps(value).encode(), 'amd64')
            value = copy.deepcopy(fixture.value)
            value['entries'][1]['size'] = rootfs.MAX_FILE + 1
            with self.assertRaises(ValueError):
                rootfs.load_manifest(json.dumps(value).encode(), 'amd64')
            with mock.patch.object(rootfs, 'MAX_ENTRIES', 1), self.assertRaises(ValueError):
                fixture.loaded()
            with mock.patch.object(rootfs, 'MAX_MANIFEST', 1), self.assertRaises(ValueError):
                rootfs.load_manifest(json.dumps(fixture.value).encode(), 'amd64')

    def test_paths_symlink_parents_escapes_chains_and_unsafe_modes_reject(self):
        rows = inventory()
        variants = []
        for path in ('/bin', '../bin', './bin', 'a//bin', 'a/../bin', 'a\\bin', 'a\nbin'):
            edited = copy.deepcopy(rows)
            edited[0]['path'] = path
            variants.append(edited)
        for target in ('/usr/bin', '../outside', 'usr/bin/sh', 'missing', 'usr//bin'):
            edited = copy.deepcopy(rows)
            edited[0]['target'] = target
            variants.append(edited)
        edited = copy.deepcopy(rows)
        edited.append({'path': 'bin/child', 'type': 'file', 'mode': 0o644, 'size': 0,
                       'sha256': hashlib.sha256(b'').hexdigest()})
        variants.append(edited)
        for mode in (0o4755, 0o2755, 0o777, 0o1777, True):
            edited = copy.deepcopy(rows)
            edited[2]['mode'] = mode
            variants.append(edited)
        edited = copy.deepcopy(rows)
        edited.append(copy.deepcopy(rows[-1]))
        variants.append(edited)
        for edited in variants:
            edited.sort(key=lambda row: row['path'])
            value = manifest(edited, b'fixture', 10240)
            with self.subTest(rows=edited), self.assertRaises(ValueError):
                rootfs.load_manifest(json.dumps(value).encode(), 'amd64')

    def test_metadata_and_archive_require_nonlinked_ordinary_files(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            link = fixture.directory / 'alias'
            link.symlink_to(fixture.archive)
            with self.assertRaises((ValueError, OSError)):
                rootfs.verify_archive(link, fixture.loaded())
            link.unlink()
            os.link(fixture.archive, link)
            with self.assertRaises(ValueError):
                fixture.verify()
            link.unlink()
            link.symlink_to(fixture.control)
            with self.assertRaises((ValueError, OSError)):
                rootfs.ordinary(link, rootfs.MAX_MANIFEST)
            link.unlink()
            if hasattr(os, 'mkfifo'):
                os.mkfifo(link)
                with self.assertRaises(ValueError):
                    rootfs.ordinary(link, rootfs.MAX_MANIFEST)
            with self.assertRaises(ValueError):
                rootfs.ordinary(fixture.archive, rootfs.MAX_COMPRESSED)

    def test_symlinked_parent_and_relative_inputs_are_refused(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            alias = fixture.directory / 'alias'
            alias.symlink_to(fixture.directory, target_is_directory=True)
            for path in (alias / 'rootfs.tar.gz', Path('rootfs.tar.gz')):
                with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                    rootfs.verify_archive(path, fixture.loaded())


class ArchiveTests(unittest.TestCase):
    def test_members_must_match_complete_inventory_not_only_outer_archive_hash(self):
        for options in ({'duplicate': True}, {'omitted': ('usr/bin/probe',)},
                        {'contents': {'usr/bin/probe': b'x' * len(INERT)}}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as name:
                fixture = Fixture(name, **options)
                with self.assertRaises(ValueError):
                    fixture.verify()

    def test_special_files_hardlinks_and_extended_headers_are_refused(self):
        kinds = (tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE,
                 tarfile.GNUTYPE_SPARSE, tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME)
        for kind in kinds:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                info = tarfile.TarInfo('unlisted')
                info.type = kind
                if kind == tarfile.LNKTYPE:
                    info.linkname = 'usr/bin/probe'
                fixture = Fixture(name, extras=((info, b''),))
                with self.assertRaises(ValueError):
                    fixture.verify()

    def test_tar_header_checksum_path_and_mode_have_independent_checks(self):
        for member_path, mode, checksum in [('../escaped', None, True),
                                            ('/escaped', None, True),
                                            ('usr//bin/sh', None, True),
                                            (None, 0o4777, True), (None, None, False)]:
            with self.subTest(path=member_path, mode=mode), tempfile.TemporaryDirectory() as name:
                fixture = Fixture(name)
                raw = bytearray(fixture.raw)
                if member_path is not None:
                    raw[:100] = member_path.encode().ljust(100, b'\0')
                if mode is not None:
                    raw[100:108] = ('%07o\0' % mode).encode()
                raw[148:156] = b' ' * 8
                value = sum(raw[:512]) if checksum else 0
                raw[148:156] = ('%06o\0 ' % value).encode()
                fixture.altered_archive(bytes(raw))
                with self.assertRaises(ValueError):
                    fixture.verify()

    def test_stream_count_end_markers_padding_and_gzip_crc_are_verified(self):
        for mutation in ('count', 'end', 'after-end', 'padding', 'crc'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as name:
                fixture = Fixture(name)
                if mutation == 'count':
                    fixture.value['stream_size'] += 512
                    fixture.write()
                elif mutation == 'crc':
                    data = bytearray(fixture.compressed)
                    data[-8] ^= 1
                    fixture.compressed = bytes(data)
                    fixture.value['archive']['sha256'] = hashlib.sha256(data).hexdigest()
                    fixture.write()
                else:
                    raw = bytearray(fixture.raw)
                    # reversed fixture: symlink header, regular header/data,
                    # two directory headers, empty file, alias symlink, end.
                    offset = {'end': 4096, 'after-end': 4608, 'padding': 1024 + len(INERT)}[mutation]
                    raw[offset] = 1
                    fixture.altered_archive(bytes(raw))
                with self.assertRaises(ValueError):
                    fixture.verify()

    def test_archive_digest_truncation_mutation_and_deadline_fail_closed(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            fixture.value['archive']['sha256'] = '0' * 64
            fixture.write()
            with self.assertRaises(ValueError):
                fixture.verify()
            fixture.value['archive']['sha256'] = hashlib.sha256(fixture.compressed).hexdigest()
            fixture.compressed = fixture.compressed[:-4]
            fixture.value['archive']['size'] = len(fixture.compressed)
            fixture.value['archive']['sha256'] = hashlib.sha256(fixture.compressed).hexdigest()
            fixture.write()
            with self.assertRaises(ValueError):
                fixture.verify()
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            with mock.patch.object(rootfs.time, 'monotonic', side_effect=(0, 121)), self.assertRaises(ValueError):
                rootfs.verify_archive(fixture.archive, fixture.value)
            original_mtime = fixture.archive.stat().st_mtime_ns

            def change_input(end):
                nonlocal original_mtime
                original_mtime += 1_000_000_000
                os.utime(fixture.archive, ns=(original_mtime, original_mtime))

            with mock.patch.object(rootfs, '_deadline', side_effect=change_input), self.assertRaises(ValueError):
                rootfs.verify_archive(fixture.archive, fixture.value)


class MetadataTests(unittest.TestCase):
    def fixture(self, name):
        rows = inventory() + [{'path': 'usr/share', 'type': 'dir', 'mode': 0o755},
                              {'path': 'usr/share/sinan-rootfs', 'type': 'dir', 'mode': 0o700},
                              {'path': 'var', 'type': 'dir', 'mode': 0o755},
                              {'path': 'var/lib', 'type': 'dir', 'mode': 0o755},
                              {'path': 'var/lib/dpkg', 'type': 'dir', 'mode': 0o755}]
        contents = {path: b'{"fixture":true,"full_ready":false}' for path in rootfs.METADATA_NAMES}
        for path, content in contents.items():
            rows.append({'path': path, 'type': 'file', 'mode': 0o600, 'size': len(content),
                         'sha256': hashlib.sha256(content).hexdigest()})
        return Fixture(name, rows=sorted(rows, key=lambda row: row['path']), contents=contents), contents

    def test_ip_profile_and_actual_package_status_are_returned_only_after_complete_stream_matches(self):
        with tempfile.TemporaryDirectory() as name:
            fixture, contents = self.fixture(name)
            value = fixture.loaded()
            self.assertEqual(rootfs.read_metadata(fixture.archive, value, sorted(contents)), contents)
            self.assertNotIn('metadata', fixture.verify())
            self.assertEqual(list(fixture.workspace.iterdir()), [])
            value['archive']['sha256'] = '0' * 64
            with self.assertRaises(ValueError):
                rootfs.read_metadata(fixture.archive, value, sorted(contents))

    def test_config_unlisted_duplicate_and_oversized_metadata_selection_rejects(self):
        with tempfile.TemporaryDirectory() as name:
            fixture, contents = self.fixture(name)
            first = 'usr/share/sinan-rootfs/provenance.json'
            for selection in ([first, first], ['root/.config/tool.json'], ['usr/bin/probe'], [], first):
                with self.subTest(selection=selection), self.assertRaises(ValueError):
                    rootfs.read_metadata(fixture.archive, fixture.loaded(), selection)
            with mock.patch.object(rootfs, 'MAX_METADATA', 1), self.assertRaises(ValueError):
                rootfs.read_metadata(fixture.archive, fixture.loaded(), [first])

    def test_package_status_uses_its_own_bounded_read_without_relaxing_proof_limits(self):
        with tempfile.TemporaryDirectory() as name:
            fixture, contents = self.fixture(name)
            with mock.patch.object(rootfs, 'MAX_METADATA', 1):
                self.assertEqual(rootfs.read_metadata(fixture.archive, fixture.loaded(),
                                                     ['var/lib/dpkg/status']),
                                 {'var/lib/dpkg/status': contents['var/lib/dpkg/status']})
                with self.assertRaises(ValueError):
                    rootfs.read_metadata(fixture.archive, fixture.loaded(),
                                         ['usr/share/sinan-rootfs/ipquality-profile.json'])
            with mock.patch.object(rootfs, 'MAX_PACKAGE_STATUS', 1), self.assertRaises(ValueError):
                rootfs.read_metadata(fixture.archive, fixture.loaded(), ['var/lib/dpkg/status'])


@unittest.skipUnless(sys.platform.startswith('linux'), 'atomic extraction requires Linux renameat2')
class ExtractionTests(unittest.TestCase):
    def test_extract_is_local_atomic_and_preserves_safe_file_modes_and_links(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            receipt = fixture.extract()
            target = fixture.workspace / 'BenchOs'
            self.assertEqual(receipt['state'], 'prepared')
            self.assertEqual((target / 'usr/bin/probe').read_bytes(), INERT)
            self.assertEqual((target / 'empty').read_bytes(), b'')
            self.assertEqual(os.readlink(target / 'bin'), 'usr/bin')
            self.assertEqual(os.readlink(target / 'usr/bin/sh'), 'probe')
            for row in fixture.rows:
                if row['type'] != 'symlink':
                    self.assertEqual(stat.S_IMODE((target / row['path']).stat().st_mode), row['mode'])
            self.assertEqual(sorted(path.name for path in fixture.workspace.iterdir()), ['BenchOs'])

    def test_existing_targets_and_public_or_linked_workspace_are_never_replaced(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            target = fixture.workspace / 'BenchOs'
            target.mkdir()
            inode = target.stat().st_ino
            with self.assertRaises(ValueError):
                fixture.extract()
            self.assertEqual(target.stat().st_ino, inode)
            target.rmdir()
            target.symlink_to(fixture.directory, target_is_directory=True)
            with self.assertRaises(ValueError):
                fixture.extract()
            target.unlink()
            fixture.workspace.chmod(0o755)
            with self.assertRaises(ValueError):
                fixture.extract()
            fixture.workspace.chmod(0o700)
            alias = fixture.directory / 'alias'
            alias.symlink_to(fixture.workspace, target_is_directory=True)
            with self.assertRaises(OSError):
                rootfs.extract(fixture.archive, fixture.loaded(), alias, 'amd64')

    def test_disk_preflight_refuses_before_creating_any_stage(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            with mock.patch.object(rootfs.os, 'fstatvfs', return_value=SimpleNamespace(f_frsize=4096, f_bavail=0)), self.assertRaises(ValueError):
                fixture.extract()
            self.assertEqual(list(fixture.workspace.iterdir()), [])

    def test_integrity_and_write_failures_clean_only_the_owned_stage(self):
        for failure in ('digest', 'write', 'stage-open'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as name:
                fixture = Fixture(name)
                sentinel = fixture.workspace / 'preserved'
                sentinel.write_bytes(b'preserve')
                if failure == 'digest':
                    fixture.value['archive']['sha256'] = '0' * 64
                    fixture.write()
                    with self.assertRaises(ValueError):
                        fixture.extract()
                else:
                    original = rootfs.os.open

                    def refuse(path, flags, *args, **kwargs):
                        if ((failure == 'write' and flags & os.O_WRONLY)
                                or (failure == 'stage-open' and str(path).startswith('.rootfs-stage-'))):
                            raise OSError('fixture IO fault')
                        return original(path, flags, *args, **kwargs)

                    with mock.patch.object(rootfs.os, 'open', side_effect=refuse), self.assertRaises((ValueError, OSError)):
                        fixture.extract()
                self.assertEqual(sentinel.read_bytes(), b'preserve')
                self.assertEqual(sorted(path.name for path in fixture.workspace.iterdir()), ['preserved'])

    def test_atomic_publication_refuses_a_destination_created_after_initial_check(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            publish, recorded = rootfs._publish, []

            def race(parent, source, destination):
                os.mkdir(destination, 0o700, dir_fd=parent)
                recorded.append(os.stat(destination, dir_fd=parent).st_ino)
                publish(parent, source, destination)

            with mock.patch.object(rootfs, '_publish', side_effect=race), self.assertRaises(ValueError):
                fixture.extract()
            self.assertEqual((fixture.workspace / 'BenchOs').stat().st_ino, recorded[0])
            self.assertEqual(sorted(path.name for path in fixture.workspace.iterdir()), ['BenchOs'])

    def test_cli_missing_inputs_and_failure_never_offer_an_online_fallback(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(name)
            fixture.archive.unlink()
            run = subprocess.run([sys.executable, str(SCRIPT), 'extract', '--archive', str(fixture.archive),
                                  '--manifest', str(fixture.control), '--arch', 'amd64',
                                  '--workspace', str(fixture.workspace)], capture_output=True, timeout=3)
            self.assertEqual(run.returncode, 70)
            self.assertEqual(run.stdout, b'')
            self.assertNotIn(b'https://', run.stderr)
            self.assertEqual(list(fixture.workspace.iterdir()), [])


    def test_cli_term_and_hup_unwind_partial_extraction_and_preserve_other_files(self):
        for name, signum in (('TERM', signal.SIGTERM), ('HUP', signal.SIGHUP)):
            with self.subTest(signal=name), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                marker = fixture.directory / 'interruption.json'
                sentinel = fixture.workspace / 'preserved'
                sentinel.write_bytes(b'preserve')
                run = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--signal-driver',
                                      name, str(marker), '--archive', str(fixture.archive),
                                      '--manifest', str(fixture.control), '--arch', 'amd64',
                                      '--workspace', str(fixture.workspace)], capture_output=True, timeout=5)
                self.assertEqual(run.returncode, 128 + signum, run.stderr)
                self.assertEqual(run.stdout, b'')
                self.assertEqual(run.stderr, b'')
                self.assertEqual(json.loads(marker.read_bytes()),
                                 {'stage_present': True, 'partial_file_present': True, 'signal': name})
                self.assertEqual(sentinel.read_bytes(), b'preserve')
                self.assertEqual(sorted(path.name for path in fixture.workspace.iterdir()), ['preserved'])


def signal_driver():
    name, marker = sys.argv[2:4]
    options = sys.argv[4:]
    workspace = Path(options[options.index('--workspace') + 1])
    original = rootfs._scan

    def scan(path, manifest, sink=None, end=None):
        @contextlib.contextmanager
        def interrupt(member):
            with sink(member) as output:
                output.write(b'owned partial fixture\n')
                output.flush()
                stages = [entry for entry in workspace.iterdir() if entry.name.startswith('.rootfs-stage-')]
                Path(marker).write_text(json.dumps({
                    'stage_present': len(stages) == 1,
                    'partial_file_present': len(stages) == 1 and (stages[0] / member).stat().st_size > 0,
                    'signal': name}))
                os.kill(os.getpid(), {'TERM': signal.SIGTERM, 'HUP': signal.SIGHUP}[name])
                yield output

        return original(path, manifest, interrupt if sink is not None else None, end)

    rootfs._scan = scan
    sys.argv = [str(SCRIPT), 'extract', *options]
    raise SystemExit(rootfs.main())


if __name__ == '__main__':
    if sys.argv[1:2] == ['--signal-driver']:
        signal_driver()
    else:
        unittest.main()
