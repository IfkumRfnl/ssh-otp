"""Fedora authselect boundaries and preservation of SSH authorization policy."""
from pathlib import Path
import unittest

from profiles.common import patch_pam
from profiles.fedora import PROFILE


FIXTURES = Path(__file__).parent / 'fixtures' / 'fedora'
MODULE = '/usr/lib64/security/pam_ssh_otp.so'


class FedoraPamTests(unittest.TestCase):
    def setUp(self):
        self.original = (FIXTURES / 'sshd').read_text()
        self.includes = {
            name: (FIXTURES / name).read_text()
            for name in ('password-auth', 'postlogin')
        }

    def patch(self, text=None):
        return patch_pam(
            self.original if text is None else text,
            MODULE, PROFILE, self.includes.__getitem__,
        )

    @staticmethod
    def rules(text, kind):
        return [line.split() for line in text.splitlines()
                if line.split() and line.split()[0].lstrip('-') == kind]

    def test_default_authselect_replaces_passwords_preserves_other_stacks(self):
        result = self.patch()
        auth = self.rules(result, 'auth')
        self.assertEqual(auth.count(['auth', 'requisite', MODULE]), 1)
        for forbidden in ('password-auth', 'pam_unix.so', 'pam_sss.so',
                          'pam_deny.so', 'pam_localuser.so', 'pam_usertype.so'):
            self.assertFalse(any(forbidden in rule for rule in auth), forbidden)
        for kind in ('account', 'session', 'password'):
            self.assertEqual(self.rules(result, kind), self.rules(self.original, kind))
        self.assertIn(['auth', 'include', 'postlogin'], auth)
        self.assertIn(['auth', 'required', 'pam_env.so'], auth)
        self.assertIn(['auth', 'required', 'pam_faildelay.so', 'delay=2000000'], auth)

    def test_direct_sepermit_authorization_gate_remains_required(self):
        original = 'auth required pam_sepermit.so\n' + self.original
        result = self.patch(original)
        self.assertIn(['auth', 'required', 'pam_sepermit.so'], self.rules(result, 'auth'))
        self.assertLess(result.index('pam_sepermit.so'), result.index(MODULE))

    def test_unknown_root_authentication_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.patch('auth sufficient pam_exec.so /usr/local/bin/custom-auth\n' + self.original)

    def test_unknown_nested_authentication_is_rejected(self):
        self.includes['password-auth'] = (
            'auth required pam_exec.so /usr/local/bin/custom-policy\n'
            + self.includes['password-auth']
        )
        with self.assertRaises(RuntimeError):
            self.patch()

    def test_postlogin_cannot_hide_password_fallback(self):
        self.includes['postlogin'] = (
            'auth sufficient pam_unix.so\n' + self.includes['postlogin']
        )
        with self.assertRaises(RuntimeError):
            self.patch()

    def test_password_dependent_ecryptfs_postlogin_is_rejected(self):
        self.includes['postlogin'] = (
            'auth optional pam_ecryptfs.so unwrap\n' + self.includes['postlogin']
        )
        with self.assertRaises(RuntimeError):
            self.patch()

    def test_mandatory_second_factor_cannot_be_removed(self):
        self.includes['password-auth'] = (
            'auth required pam_u2f.so cue\n' + self.includes['password-auth']
        )
        with self.assertRaises(RuntimeError):
            self.patch()

    def test_custom_selector_jump_cannot_skip_burner(self):
        self.includes['password-auth'] = self.includes['password-auth'].replace(
            '[default=1 ignore=ignore success=ok]', '[default=2 ignore=ignore success=ok]', 1,
        )
        with self.assertRaises(RuntimeError):
            self.patch()


if __name__ == '__main__':
    unittest.main()
