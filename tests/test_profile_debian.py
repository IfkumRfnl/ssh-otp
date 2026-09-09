"""Preserve Debian/Ubuntu policy while replacing password authentication."""
from pathlib import Path
import unittest

from profiles.common import patch_pam
from profiles.debian import PROFILE


FIXTURES = Path(__file__).parent / 'fixtures' / 'debian'
MODULE = '/usr/local/lib/security/pam_ssh_otp.so'


class DebianProfileTests(unittest.TestCase):
    def setUp(self):
        self.original = (FIXTURES / 'sshd').read_text()
        self.includes = {
            name: (FIXTURES / name).read_text()
            for name in ('common-auth', 'common-account', 'common-session',
                         'common-password')
        }

    def patch(self, text=None):
        return patch_pam(self.original if text is None else text, MODULE,
                         PROFILE, self.includes.__getitem__)

    def test_replaces_credentials_without_changing_other_policy(self):
        for locale in ('envfile=/etc/default/locale',
                       'user_readenv=1 envfile=/etc/default/locale'):
            with self.subTest(locale=locale):
                original = self.original.replace(
                    'envfile=/etc/default/locale', locale)
                result = self.patch(original)
                self.assertEqual(result, original.replace(
                    '@include common-auth', f'auth requisite {MODULE}'))
                self.assertEqual(self.patch(result), result)

    def test_rejects_credential_include_with_non_auth_policy(self):
        self.includes['common-auth'] += 'account required pam_access.so\n'
        with self.assertRaises(RuntimeError):
            self.patch()

    def test_rejects_custom_direct_authentication(self):
        with self.assertRaises(RuntimeError):
            self.patch('auth sufficient pam_permit.so\n' + self.original)

    def test_rejects_authentication_hidden_in_retained_account_include(self):
        self.includes['common-account'] += 'auth sufficient pam_unix.so\n'
        with self.assertRaises(RuntimeError):
            self.patch()

    def test_rejects_custom_policy_inside_credential_stack(self):
        self.includes['common-auth'] += 'auth required pam_custom_mfa.so\n'
        with self.assertRaises(RuntimeError):
            self.patch()


if __name__ == '__main__':
    unittest.main()
