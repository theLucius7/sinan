#!/usr/bin/env python3
"""Exercise static executable admission with private synthetic tar members."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('execution_inventory', ROOT / 'tools/nodequality-execution-inventory.py')
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


def elf(machine=62):
    content = bytearray(64)
    content[:6] = b'\x7fELF\x02\x01'
    content[18:20] = machine.to_bytes(2, 'little')
    return bytes(content) + b'Never execute this synthetic file.\n'


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sinan-executable-inventory-')
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def archive(self, rows):
        path = self.root / 'rootfs.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, content, mode, kind in rows:
                member = tarfile.TarInfo(name)
                member.mode, member.size = mode, len(content)
                if kind == 'link':
                    member.type, member.linkname, member.size = tarfile.SYMTYPE, '../../outside', 0
                    archive.addfile(member)
                else:
                    archive.addfile(member, io.BytesIO(content))
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def scan(self, rows, architecture='amd64'):
        path, digest = self.archive(rows)
        return inventory.scan(path, architecture, digest)

    def declaration(self, report):
        path = self.root / 'declared.json'
        path.write_text(json.dumps({name: report[name] for name in ('schema', 'architecture', 'archive', 'files')}))
        return path

    def test_unsigned_executable_without_mode_and_script_are_both_inventoried(self):
        report = self.scan([
            ('BenchOs/usr/bin/speedtest', elf(), 0o644, 'ordinary'),
            ('BenchOs/usr/local/bin/helper', b'#!/bin/sh\nexit 0\n', 0o644, 'ordinary'),
            ('BenchOs/usr/share/doc/tool/copyright', b'Unknown rights; do not treat as permission.', 0o644, 'ordinary'),
            ('BenchOs/root/.config/ookla/speedtest-cli.json', b'PRIVATE_CONFIGURATION', 0o600, 'ordinary'),
            ('BenchOs/usr/bin/linked', b'', 0o777, 'link')])
        self.assertEqual([row['format'] for row in report['files']], ['elf', 'script'])
        self.assertEqual(report['files'][0]['sha256'], hashlib.sha256(elf()).hexdigest())
        self.assertEqual(report['configuration_files_not_read'], 1)
        self.assertEqual(report['links_not_followed'], 1)
        self.assertNotIn('PRIVATE_CONFIGURATION', json.dumps(report))
        inventory.declared_identities(self.declaration(report), report)
        self.assertFalse(report['full_start_allowed'])
        self.assertFalse(report['rights_verified'])

    def test_missing_extra_duplicate_and_one_byte_changed_declarations_are_refused(self):
        report = self.scan([('BenchOs/usr/bin/speedtest', elf(), 0o755, 'ordinary')])
        for mutation in ('missing', 'extra', 'duplicate', 'changed'):
            declared = {name: copy.deepcopy(report[name]) for name in ('schema', 'architecture', 'archive', 'files')}
            if mutation == 'missing':
                declared['files'].clear()
            elif mutation == 'extra':
                extra = dict(declared['files'][0], path='BenchOs/usr/bin/unregistered')
                declared['files'].append(extra)
            elif mutation == 'duplicate':
                declared['files'].append(copy.deepcopy(declared['files'][0]))
            else:
                declared['files'][0]['sha256'] = '0' * 64
            path = self.root / 'declared.json'
            path.write_text(json.dumps(declared))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                inventory.declared_identities(path, report)

    def test_private_path_executables_remain_explicit_omissions_even_when_declaration_matches(self):
        report = self.scan([
            ('BenchOs/usr/bin/public-tool', elf(), 0o755, 'ordinary'),
            ('BenchOs/root/renamed-tool', b'PRIVATE_EXECUTABLE_DO_NOT_READ', 0o755, 'ordinary'),
            ('BenchOs/etc/init.d/helper', b'PRIVATE_EXECUTABLE_DO_NOT_READ', 0o750, 'ordinary'),
            ('BenchOs/home/operator/library', b'PRIVATE_BYTES_DO_NOT_READ', 0o600, 'ordinary')])
        self.assertEqual(report['configuration_files_not_read'], 3)
        self.assertEqual([row['path'] for row in report['unread_executable_files']],
                         ['BenchOs/etc/init.d/helper', 'BenchOs/root/renamed-tool'])
        self.assertEqual(report['unread_executable_files'][1]['mode'], 0o755)
        self.assertEqual(report['inventory_scope'], 'public-ordinary-executable-identities')
        self.assertFalse(report['complete_execution_inventory'])
        self.assertNotIn('PRIVATE_EXECUTABLE_DO_NOT_READ', json.dumps(report))
        self.assertNotIn('PRIVATE_BYTES_DO_NOT_READ', json.dumps(report))
        self.assertNotIn('sha256', report['unread_executable_files'][0])
        inventory.declared_identities(self.declaration(report), report)
        self.assertFalse(report['full_start_allowed'])
        self.assertFalse(report['rights_verified'])

    def test_private_configuration_contents_are_never_opened(self):
        path, digest = self.archive([
            ('BenchOs/root/.config/tool/config.json', b'PRIVATE_VALUE', 0o600, 'ordinary'),
            ('BenchOs/etc/credential', b'PRIVATE_VALUE', 0o600, 'ordinary'),
            ('BenchOs/root/helper', b'PRIVATE_VALUE', 0o700, 'ordinary')])
        with mock.patch.object(tarfile.TarFile, 'extractfile', side_effect=AssertionError('private contents read')):
            report = inventory.scan(path, 'amd64', digest)
        self.assertEqual(report['files'], [])
        self.assertEqual(report['configuration_files_not_read'], 3)
        self.assertEqual(len(report['unread_executable_files']), 1)

    def test_sparse_regular_files_are_rejected_before_reading_content(self):
        path = self.root / 'rootfs.tar.gz'
        with tarfile.open(path, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo('BenchOs/usr/bin/tool')
            member.size, member.mode = 16, 0o755
            member.pax_headers = {'GNU.sparse.map': '0,16', 'GNU.sparse.size': '16'}
            archive.addfile(member, io.BytesIO(b'x' * 16))
        with mock.patch.object(tarfile.TarFile, 'extractfile', side_effect=AssertionError('sparse contents read')):
            with self.assertRaisesRegex(ValueError, 'sparse rootfs'):
                inventory.scan(path, 'amd64', hashlib.sha256(path.read_bytes()).hexdigest())

    def test_wrong_archive_digest_and_architecture_are_refused_without_execution(self):
        path, digest = self.archive([('BenchOs/usr/bin/tool', elf(183), 0o755, 'ordinary')])
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            inventory.scan(path, 'arm64', '0' * 64)
        with self.assertRaisesRegex(ValueError, 'architecture mismatch'):
            inventory.scan(path, 'amd64', digest)
        report = inventory.scan(path, 'arm64', digest)
        self.assertEqual(report['files'][0]['architecture'], 'arm64')

    def test_traversal_absolute_and_duplicate_member_names_fail(self):
        for path in ('/BenchOs/usr/bin/tool', 'BenchOs/../tool', 'BenchOs//tool', 'Other/usr/bin/tool'):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'path'):
                self.scan([(path, elf(), 0o755, 'ordinary')])
        with self.assertRaisesRegex(ValueError, 'duplicate member'):
            self.scan([('BenchOs/usr/bin/tool', elf(), 0o755, 'ordinary')] * 2)

    def test_deadline_byte_and_member_bounds_fail_closed(self):
        rows = [('BenchOs/usr/bin/tool', elf(), 0o755, 'ordinary')]
        with mock.patch.object(inventory, 'SECONDS', -1), self.assertRaisesRegex(ValueError, 'deadline'):
            self.scan(rows)
        with mock.patch.object(inventory, 'MAX_MEMBER', 1), self.assertRaisesRegex(ValueError, 'member.*byte'):
            self.scan(rows)
        with mock.patch.object(inventory, 'MAX_MEMBERS', 0), self.assertRaisesRegex(ValueError, 'member limit'):
            self.scan(rows)
        with mock.patch.object(inventory, 'MAX_EXPANDED', 1), self.assertRaisesRegex(ValueError, 'expanded archive'):
            self.scan(rows)

    def test_pax_extension_is_bounded_before_standard_parser_buffers_it(self):
        path = self.root / 'rootfs.tar.gz'
        with tarfile.open(path, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo('BenchOs/usr/bin/tool')
            member.size, member.mode = len(elf()), 0o755
            member.pax_headers = {'comment': 'x' * (inventory.MAX_EXTENSION + 1)}
            archive.addfile(member, io.BytesIO(elf()))
        with self.assertRaisesRegex(ValueError, 'extension header'):
            inventory.scan(path, 'amd64', hashlib.sha256(path.read_bytes()).hexdigest())

    def test_symlink_archive_and_declared_input_do_not_follow_targets(self):
        path, digest = self.archive([('BenchOs/usr/bin/tool', elf(), 0o755, 'ordinary')])
        linked = self.root / 'linked.tar.gz'
        linked.symlink_to(path)
        with self.assertRaises(OSError):
            inventory.scan(linked, 'amd64', digest)
        report = inventory.scan(path, 'amd64', digest)
        declared = self.declaration(report)
        linked_declaration = self.root / 'linked.json'
        linked_declaration.symlink_to(declared)
        with self.assertRaises(OSError):
            inventory.declared_identities(linked_declaration, report)


if __name__ == '__main__':
    unittest.main()
