#!/usr/bin/env python3
"""Keep current improvements separate from exact historical signed identities."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
import nodequality_history as history


class HistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='sinan-nodequality-history-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.contents = {name: history.source(name) for name in history.IDENTITIES}
        for name, content in self.contents.items():
            (self.root / name).write_bytes(content)

    def test_current_runner_report_and_rootfs_cannot_relabel_historical_sources(self):
        current = history.DIRECTORY.parent
        with mock.patch.object(history, 'DIRECTORY', self.root):
            for name in history.IDENTITIES:
                target = self.root / name
                target.write_bytes((current / name).read_bytes())
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    history.source(name)
                target.write_bytes(self.contents[name])
        self.assertIn(b'version=a92fca6c0067df29ddd03fdc2fee6f3000f64545-r19\n', self.contents['runner.sh.tmpl'])
        self.assertIn(b'version=a92fca6c0067df29ddd03fdc2fee6f3000f64545-r22\n', (current / 'runner.sh.tmpl').read_bytes())

    def test_unknown_symlink_fifo_and_modified_sources_are_rejected(self):
        with mock.patch.object(history, 'DIRECTORY', self.root):
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                history.source('../report.py')
            path = self.root / 'report.py'
            path.write_bytes(self.contents['report.py'] + b'\n# altered\n')
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                history.source('report.py')
            path.unlink()
            path.symlink_to(history.DIRECTORY.parent / 'report.py')
            with self.assertRaises(OSError):
                history.source('report.py')
            path.unlink()
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, 'ordinary file'):
                history.source('report.py')

    def test_historical_rootfs_module_is_compiled_from_verified_bytes(self):
        with mock.patch.object(history, 'DIRECTORY', self.root):
            module = history.rootfs_module()
            self.assertEqual(module.MAX_ENTRIES, 100000)
            path = self.root / 'rootfs.py'
            path.write_bytes(b"raise AssertionError('modified file must not execute')\n")
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                history.rootfs_module()


class NativeHistoryTests(unittest.TestCase):
    def test_current_native_runner_and_report_cannot_replace_native_r1_sources(self):
        current = history.NATIVE_DIRECTORY.parent
        originals = {name: history.native_source(name) for name in history.NATIVE_IDENTITIES}
        with tempfile.TemporaryDirectory(prefix='sinan-native-history-') as temporary:
            directory = Path(temporary)
            with mock.patch.object(history, 'NATIVE_DIRECTORY', directory):
                for name, content in originals.items():
                    path = directory / name
                    path.write_bytes(content)
                    self.assertEqual(history.native_source(name), content)
                    path.write_bytes((current / name).read_bytes())
                    with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'identity mismatch'):
                        history.native_source(name)
                with self.assertRaisesRegex(ValueError, 'unsupported'):
                    history.native_source('../native-report.py')
        self.assertIn(b'version=a92fca6c0067df29ddd03fdc2fee6f3000f64545-sinan-native-r1\n',
                      originals['native-runner.sh.tmpl'])
        self.assertIn(b'version=a92fca6c0067df29ddd03fdc2fee6f3000f64545-sinan-native-r2\n',
                      (current / 'native-runner.sh.tmpl').read_bytes())


if __name__ == '__main__':
    unittest.main()
