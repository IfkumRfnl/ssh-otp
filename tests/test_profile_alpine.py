"""Alpine packaging policy must survive burner authentication replacement."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from profiles.alpine import PROFILE
from profiles.common import patch_pam
from profiles.runtime import check_pam_daemon, service_command


FIXTURES = Path(__file__).parent / 'fixtures' / 'alpine'
MODULE = '/usr/local/lib/security/pam_ssh_otp.so'


def read_include(name):
    return (FIXTURES / name).read_text()


def directives(text):
    return [line.split() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith('#')]


class AlpinePamTests(unittest.TestCase):
    def test_burner_replaces_credentials_without_losing_policy(self):
        original = read_include('sshd')
        result = patch_pam(original, MODULE, PROFILE, read_include)
        rules = directives(result)
        self.assertEqual([row for row in rules if MODULE in row],
                         [['auth', 'requisite', MODULE]])
        self.assertNotIn(['auth', 'include', 'base-auth'], rules)
        self.assertFalse(any(row[0].lstrip('-') == 'auth' and 'pam_unix.so' in row
                             for row in rules))
        self.assertIn(['auth', 'required', 'pam_nologin.so'], rules)
        self.assertIn(['auth', 'required', 'pam_env.so'], rules)
        non_auth = lambda text: [row for row in directives(text)
                                 if row[0].lstrip('-') != 'auth']
        self.assertEqual(non_auth(result), non_auth(original))

    def test_custom_root_authentication_is_rejected(self):
        text = 'auth sufficient pam_permit.so\n' + read_include('sshd')
        with self.assertRaises(RuntimeError):
            patch_pam(text, MODULE, PROFILE, read_include)

    def test_custom_nested_authentication_is_rejected(self):
        def custom_include(name):
            text = read_include(name)
            if name == 'base-auth':
                text += 'auth required pam_exec.so /usr/local/sbin/site-auth\n'
            return text

        with self.assertRaises(RuntimeError):
            patch_pam(read_include('sshd'), MODULE, PROFILE, custom_include)

    def test_unknown_site_authentication_include_is_rejected(self):
        text = read_include('sshd').replace('base-auth', 'site-auth')
        with self.assertRaises(RuntimeError):
            patch_pam(text, MODULE, PROFILE, read_include)


class AlpineDaemonTests(unittest.TestCase):
    def test_deleted_non_pam_daemon_is_rejected(self):
        with patch('profiles.runtime.Path.iterdir', return_value=[Path('/proc/123')]), \
                patch('profiles.runtime.os.readlink', return_value='/usr/sbin/sshd (deleted)'):
            with self.assertRaises(RuntimeError):
                check_pam_daemon(PROFILE, '/usr/sbin/sshd.pam')


@unittest.skipUnless(Path('/run/.containerenv').exists() and Path('/usr/sbin/sshd.pam').exists()
                     and shutil.which('rc-service'),
                     'requires disposable Alpine container with OpenRC')
class AlpineReloadTests(unittest.TestCase):
    def test_reload_after_removing_usepam_keeps_running_daemon(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertTrue(any(int(row.split()[0]) == 0 and int(row.split()[1]) != 0
                            for row in Path('/proc/self/uid_map').read_text().splitlines()),
                        'refusing host-root identity mapping')
        name = 'ssh-otp-reload-test'
        pidfile = Path(f'/run/{name}.pid')
        service = Path(f'/etc/init.d/{name}')
        settings = Path(f'/etc/conf.d/{name}')
        with tempfile.TemporaryDirectory(prefix='ssh-otp-reload-', dir='/root') as directory:
            root = Path(directory)
            hostkey = root / 'hostkey'
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(hostkey)],
                           check=True)
            dropin = root / 'pam.conf'
            dropin.write_text('UsePAM yes\n')
            config = root / 'sshd_config'
            config.write_text(f'Include {dropin}\nHostKey {hostkey}\n'
                              'Port 22223\nListenAddress 127.0.0.1\n'
                              'PasswordAuthentication no\nKbdInteractiveAuthentication no\n')
            Path('/run/openrc').mkdir(exist_ok=True)
            Path('/run/openrc/softlevel').write_text('default\n')
            service.symlink_to('/etc/init.d/sshd')
            settings.write_text(f'cfgfile="{config}"\nsshd_disable_keygen=yes\n')
            try:
                subprocess.run(['rc-service', '--nodeps', name, 'start'], check=True,
                               capture_output=True, text=True)
                pid = int(pidfile.read_text())
                daemon = os.readlink(f'/proc/{pid}/exe')
                self.assertEqual(daemon, '/usr/sbin/sshd.pam')
                # Same transition as uninstall: the managed UsePAM setting is
                # gone before reload; the listener must survive without restart.
                dropin.unlink()
                subprocess.run(service_command(PROFILE, daemon, name), check=True,
                               capture_output=True, text=True)
                deadline = time.monotonic() + 5
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', 22223), timeout=0.2) as connection:
                            self.assertTrue(connection.recv(256).startswith(b'SSH-2.0-'))
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)
                # OpenSSH may fork while re-executing after SIGHUP.
                current_pid = int(pidfile.read_text())
                self.assertEqual(os.readlink(f'/proc/{current_pid}/exe'), daemon)
            finally:
                # Restore executable selection for the packaged stop command.
                dropin.write_text('UsePAM yes\n')
                subprocess.run(['rc-service', '--nodeps', name, 'stop'],
                               capture_output=True, text=True)
                settings.unlink()
                service.unlink()


if __name__ == '__main__':
    unittest.main()
