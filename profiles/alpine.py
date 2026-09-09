"""Alpine's PAM-enabled OpenSSH variant and OpenRC service."""
from .common import Profile


PROFILE = Profile(
    name='alpine',
    os_ids=('alpine',),
    id_like=(),
    systemd_services=(),
    openrc_service='sshd',
    auth_includes=('base-auth',),
    retained_auth_modules=('pam_nologin.so', 'pam_env.so',
                           'pam_gnome_keyring.so', 'pam_kwallet5.so'),
    packages=('openssh-server-pam', 'openssh-server-common-openrc', 'linux-pam',
              'python3', 'musl-dev'),
)
