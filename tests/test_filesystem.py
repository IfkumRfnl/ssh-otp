"""Real ownership/symlink regressions; run only in disposable rootless containers."""
import os
from pathlib import Path
import tempfile
import unittest

from profiles.filesystem import safe_parent, trusted_file


@unittest.skipUnless(Path('/run/.containerenv').exists(), 'requires disposable Podman container')
class TrustedPathTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertTrue(any(int(row.split()[0]) == 0 and int(row.split()[1]) != 0
                            for row in Path('/proc/self/uid_map').read_text().splitlines()),
                        'refusing host-root identity mapping')
        self.temp = tempfile.TemporaryDirectory(prefix='ssh-otp-path-test-', dir='/root')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.safe = self.root / 'safe'
        self.safe.mkdir(mode=0o755)
        self.file = self.safe / 'file'
        self.file.write_text('fixture')
        self.file.chmod(0o644)

    def test_root_owned_directory_alias_is_supported(self):
        alias = self.root / 'alias'
        alias.symlink_to('safe')
        safe_parent(alias / 'created/file')
        self.assertTrue((self.safe / 'created').is_dir())
        self.assertEqual(trusted_file(alias / 'file'), self.file)

    def test_writable_intermediate_cannot_be_hidden_by_resolution(self):
        writable = self.root / 'writable'
        writable.mkdir()
        writable.chmod(0o777)
        (writable / 'next').symlink_to(self.safe)
        alias = self.root / 'alias'
        alias.symlink_to('writable/next')
        with self.assertRaises(RuntimeError):
            safe_parent(alias / 'created/file')
        with self.assertRaises(RuntimeError):
            trusted_file(alias / 'file')
        self.assertFalse((self.safe / 'created').exists())

    def test_user_owned_file_alias_is_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.file)
        os.chown(alias, 1000, 1000, follow_symlinks=False)
        with self.assertRaises(RuntimeError):
            trusted_file(alias)
        self.assertEqual(self.file.read_text(), 'fixture')

    def test_read_preflight_does_not_create_missing_directories(self):
        with self.assertRaises(FileNotFoundError):
            trusted_file(self.root / 'missing/path/file')
        self.assertFalse((self.root / 'missing').exists())

    def test_cyclic_directory_alias_is_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to('alias')
        with self.assertRaises(RuntimeError):
            safe_parent(alias / 'file')


if __name__ == '__main__':
    unittest.main()
