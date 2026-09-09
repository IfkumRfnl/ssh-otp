"""Alpine packaging policy must survive burner authentication replacement."""
from pathlib import Path
import unittest

from profiles.alpine import PROFILE
from profiles.common import patch_pam


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


if __name__ == '__main__':
    unittest.main()
