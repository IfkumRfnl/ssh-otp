"""Arch Linux's OpenSSH and pambase configuration."""
from .common import Profile


PROFILE = Profile(
    name='arch',
    os_ids=('arch',),
    id_like=('arch',),
    systemd_services=('sshd.service',),
    openrc_service=None,
    auth_includes=('system-remote-login', 'system-login', 'system-auth'),
    retained_auth_modules=(
        'pam_shells.so', 'pam_nologin.so', 'pam_env.so', 'pam_faillock.so',
    ),
    packages=('openssh', 'pam', 'pambase'),
)
