"""Filesystem failure regressions; run as mapped namespace root, never host root."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'install.py'
spec = importlib.util.spec_from_file_location('installer', SOURCE)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerRecoveryTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest('requires mapped namespace root for real file ownership checks')
        if not any(int(row.split()[0]) == 0 and int(row.split()[1]) != 0
                   for row in Path('/proc/self/uid_map').read_text().splitlines()):
            self.fail('refusing host-root execution')
        self.temp = tempfile.TemporaryDirectory(prefix='ssh-otp-install-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        paths = {
            'STATE': self.root / 'state', 'PAM': self.root / 'pam/sshd',
            'CLI': self.root / 'bin/ssh-otp', 'MODULE': self.root / 'lib/pam_ssh_otp.so',
            'MAN': self.root / 'man/ssh-otp.1', 'DROPIN': self.root / 'ssh/00-ssh-otp.conf',
            'RUNTIME': self.root / 'runtime',
        }
        for name, value in paths.items():
            self.stack.enter_context(patch.object(installer, name, value, create=True))
        self.modes = {installer.CLI: 0o4755, installer.MODULE: 0o644,
                      installer.MAN: 0o644, installer.DROPIN: 0o644}
        self.stack.enter_context(patch.object(installer, 'FILE_MODES', self.modes, create=True))
        self.stack.enter_context(patch.object(installer, '__file__', str(self.root / 'install.py')))
        self.stack.enter_context(patch.object(installer, 'safe_parent', self.safe_parent))
        self.stack.enter_context(patch.object(installer, 'command', self.command))
        self.stack.enter_context(patch.object(installer, 'validate', lambda user: None))
        self.args = SimpleNamespace(user='root', no_reload=True)
        self.original = b'@include common-auth\n@include common-account\n@include common-session\n@include common-password\n'
        self.write(installer.PAM, self.original)
        for name, content in [('account', b'account required pam_unix.so\n'),
                              ('session', b'session required pam_permit.so\n'),
                              ('password', b'password required pam_unix.so\n')]:
            self.write(installer.PAM.parent / ('common-' + name), content)
        self.write(self.root / 'zig-out/bin/ssh-otp', b'\x7fELFtest-cli')
        self.write(self.root / 'zig-out/lib/libpam_ssh_otp.so', b'\x7fELFtest-pam')
        self.write(self.root / 'ssh-otp.1', b'test manual')
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def safe_parent(self, path):
        if not path.is_relative_to(self.root):
            raise AssertionError(f'fixture escaped temporary directory: {path}')
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, path, data, mode=0o644):
        self.safe_parent(path)
        path.write_bytes(data)
        path.chmod(mode)

    def command(self, *args):
        return 'authenticationmethods any\npasswordauthentication no\nkbdinteractiveauthentication no\n'

    def install(self):
        installer.install(self.args)

    def snapshot(self):
        paths = [installer.PAM, *self.modes, installer.STATE / 'manifest.json',
                 installer.STATE / 'sshd.pam.original']
        return {path: (path.read_bytes(), path.stat().st_mode & 0o7777) for path in paths}

    def assert_restored(self, snapshot):
        for path, (data, mode) in snapshot.items():
            self.assertEqual(path.read_bytes(), data, str(path))
            self.assertEqual(path.stat().st_mode & 0o7777, mode, str(path))

    def test_failed_backup_removes_incomplete_state_and_allows_retry(self):
        original_replace = installer.replace
        def fail_backup(path, *args, **kwargs):
            if path.name == 'sshd.pam.original':
                raise OSError('backup write failed')
            return original_replace(path, *args, **kwargs)
        with patch.object(installer, 'replace', fail_backup):
            with self.assertRaises(OSError):
                self.install()
        self.assertEqual(installer.PAM.read_bytes(), self.original)
        self.assertFalse(installer.STATE.exists())
        self.assertTrue(all(not path.exists() for path in self.modes))
        self.install()
        self.assertNotEqual(installer.PAM.read_bytes(), self.original)

    def test_dropin_removal_failure_restores_installed_configuration(self):
        self.install()
        snapshot = self.snapshot()
        original_unlink = Path.unlink
        def fail_dropin(path, *args, **kwargs):
            if path == installer.DROPIN:
                raise OSError('dropin removal failed')
            return original_unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', fail_dropin):
            with self.assertRaises(OSError):
                installer.uninstall(self.args)
        self.assert_restored(snapshot)

    def test_partial_binary_removal_restores_complete_installation(self):
        self.install()
        snapshot = self.snapshot()
        original_unlink = Path.unlink
        def fail_module(path, *args, **kwargs):
            if path == installer.MODULE:
                raise OSError('module removal failed')
            return original_unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', fail_module):
            with self.assertRaises(OSError):
                installer.uninstall(self.args)
        self.assert_restored(snapshot)

    def test_recovery_failure_preserves_primary_error_and_required_module(self):
        primary = RuntimeError('primary validation failure')
        original_replace = installer.replace
        stderr = io.StringIO()
        def fail_pam_restore(path, data, *args, **kwargs):
            if path == installer.PAM and data == self.original:
                raise OSError('secondary restore failure')
            return original_replace(path, data, *args, **kwargs)
        with patch.object(installer, 'validate', side_effect=primary), \
             patch.object(installer, 'replace', fail_pam_restore), contextlib.redirect_stderr(stderr):
            with self.assertRaises(RuntimeError) as caught:
                self.install()
        self.assertIs(caught.exception, primary)
        self.assertIn('secondary restore failure', stderr.getvalue())
        self.assertFalse(installer.CLI.exists())
        self.assertFalse(installer.DROPIN.exists())
        self.assertTrue(installer.MODULE.exists())
        self.assertEqual((installer.STATE / 'sshd.pam.original').read_bytes(), self.original)

    def test_partial_state_cleanup_restores_recovery_files(self):
        self.install()
        snapshot = self.snapshot()
        original_rmtree = installer.shutil.rmtree
        def fail_state(path, *args, **kwargs):
            if path == installer.STATE:
                (path / 'manifest.json').unlink()
                raise OSError('state cleanup failed')
            return original_rmtree(path, *args, **kwargs)
        with patch.object(installer.shutil, 'rmtree', fail_state):
            with self.assertRaises(OSError):
                installer.uninstall(self.args)
        self.assert_restored(snapshot)

    def test_metadata_changes_are_rejected_before_configuration_changes(self):
        self.install()
        pam = installer.PAM.read_bytes()
        for mode, gid in [(0o0755, 0), (0o4755, 1)]:
            with self.subTest(mode=mode, gid=gid):
                os.chown(installer.CLI, 0, gid)
                installer.CLI.chmod(mode)
                with self.assertRaises(RuntimeError):
                    installer.uninstall(self.args)
                self.assertEqual(installer.PAM.read_bytes(), pam)
                self.assertTrue(installer.MODULE.exists())
        os.chown(installer.CLI, 0, 0)
        installer.CLI.chmod(0o4755)

    def test_malformed_manifest_reports_action_error_without_mutation(self):
        self.install()
        pam = installer.PAM.read_bytes()
        stderr = io.StringIO()
        self.write(installer.STATE / 'manifest.json', b'{broken', 0o600)
        with patch('sys.argv', ['install.py', 'uninstall']), contextlib.redirect_stderr(stderr):
            self.assertEqual(installer.main(), 1)
        self.assertIn('Uninstall failed:', stderr.getvalue())
        self.assertEqual(installer.PAM.read_bytes(), pam)
        self.assertTrue(installer.CLI.exists())

    def test_install_requires_explicit_user_before_mutation(self):
        with patch('sys.argv', ['install.py', 'install']), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                installer.main()
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(installer.STATE.exists())


if __name__ == '__main__':
    unittest.main()
