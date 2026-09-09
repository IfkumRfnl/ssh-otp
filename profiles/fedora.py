"""Fedora and RHEL-family OpenSSH policy; sources accompany the PAM fixtures."""
from .common import Profile


PROFILE = Profile(
    name='fedora',
    os_ids=('fedora', 'rhel', 'centos'),
    id_like=('fedora', 'rhel'),
    systemd_services=('sshd.service',),
    openrc_service=None,
    auth_includes=('password-auth',),
    # Older installations may put this SELinux authorization gate in auth.
    retained_auth_modules=(
        'pam_sepermit.so', 'pam_env.so', 'pam_faildelay.so', 'pam_faillock.so',
    ),
    # Default authselect postlogin has session rules only. Audit its actual
    # contents: with-ecryptfs and custom authentication are not supported.
    retained_auth_includes=('postlogin',),
    packages=('openssh-server', 'pam', 'policycoreutils'),
    selinux=True,
)
