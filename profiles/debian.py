"""Debian and Ubuntu's openssh-server PAM layout."""
from .common import Profile


PROFILE = Profile(
    name='debian',
    os_ids=('debian', 'ubuntu'),
    id_like=(),
    systemd_services=('ssh', 'sshd'),
    openrc_service=None,
    auth_includes=('common-auth',),
    packages=('openssh-server', 'libpam-modules', 'libpam-runtime'),
)
