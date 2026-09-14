"""OpenSSH 10.5 changed diagnostic keyword case, not configuration semantics."""
import unittest

from install import parse_sshd_settings


class SshdSettingsTests(unittest.TestCase):
    def test_keyword_normalization_preserves_values(self):
        output = ('PasswordAuthentication\tno\n'
                  'AuthenticationMethods publickey keyboard-interactive:pam\n'
                  'authorizedkeysfile /CaseSensitive/%u\n')
        self.assertEqual(parse_sshd_settings(output), {
            'passwordauthentication': 'no',
            'authenticationmethods': 'publickey keyboard-interactive:pam',
            'authorizedkeysfile': '/CaseSensitive/%u',
        })


if __name__ == '__main__':
    unittest.main()
