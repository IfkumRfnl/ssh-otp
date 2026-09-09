"""Protect Arch's nested authorization policy while replacing credentials."""
from pathlib import Path
import unittest

from profiles.arch import PROFILE
from profiles.common import patch_pam


FIXTURES = Path(__file__).parent / 'fixtures' / 'arch'
MODULE = '/usr/local/lib/security/pam_ssh_otp.so'


class ArchProfileTests(unittest.TestCase):
    def setUp(self):
        self.stacks = {
            name: (FIXTURES / name).read_text()
            for name in ('sshd', 'system-remote-login', 'system-login', 'system-auth')
        }

    def patch(self):
        return patch_pam(self.stacks['sshd'], MODULE, PROFILE, self.stacks.__getitem__)

    def auth_rules(self, text):
        rules = []
        for line in text.splitlines():
            parts = line.split()
            if not parts or parts[0].lstrip('-') != 'auth':
                continue
            if parts[1] in ('include', 'substack'):
                rules.extend(self.auth_rules(self.stacks[parts[2]]))
            else:
                rules.append(' '.join(parts))
        return rules

    def test_burner_replaces_credentials_without_losing_nested_authorization(self):
        patched = self.patch()
        rules = self.auth_rules(patched)
        burner = f'auth requisite {MODULE}'
        self.assertEqual(rules.count(burner), 1)
        self.assertIn('auth required pam_shells.so', rules)
        self.assertIn('auth requisite pam_nologin.so', rules)
        self.assertIn('auth required pam_faillock.so preauth', rules)
        self.assertIn('auth required pam_env.so', rules)
        self.assertIn('auth required pam_faillock.so authsucc', rules)
        self.assertLess(rules.index('auth requisite pam_nologin.so'), rules.index(burner))
        self.assertLess(rules.index('auth required pam_faillock.so preauth'), rules.index(burner))
        self.assertGreater(rules.index('auth required pam_faillock.so authsucc'), rules.index(burner))
        for rule in rules:
            self.assertNotIn('pam_unix.so', rule)
            self.assertNotIn('pam_systemd_home.so', rule)
            self.assertNotIn('authfail', rule)

    def test_key_login_account_and_session_stacks_are_untouched(self):
        patched = self.patch()
        original_policy = [
            line for line in self.stacks['sshd'].splitlines()
            if line.split() and line.split()[0] in ('account', 'password', 'session')
        ]
        patched_policy = [
            line for line in patched.splitlines()
            if line.split() and line.split()[0] in ('account', 'password', 'session')
        ]
        self.assertEqual(patched_policy, original_policy)

    def test_unknown_root_authentication_is_rejected(self):
        self.stacks['sshd'] += 'auth sufficient pam_custom.so\n'
        with self.assertRaises(RuntimeError):
            self.patch()

    def test_unknown_nested_authorization_is_not_silently_discarded(self):
        self.stacks['system-login'] = (
            'auth required pam_custom_policy.so\n' + self.stacks['system-login']
        )
        with self.assertRaises(RuntimeError):
            self.patch()

    def test_unknown_nested_credential_provider_is_rejected(self):
        self.stacks['system-auth'] += 'auth sufficient pam_custom_credentials.so\n'
        with self.assertRaises(RuntimeError):
            self.patch()

    def test_recursive_authentication_include_is_rejected(self):
        self.stacks['system-auth'] = 'auth include system-remote-login\n'
        with self.assertRaises(RuntimeError):
            self.patch()


if __name__ == '__main__':
    unittest.main()
