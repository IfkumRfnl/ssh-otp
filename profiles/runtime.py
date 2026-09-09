"""Machine-specific SSH discovery; never start services or weaken SELinux."""
from pathlib import Path
import os
import shutil
import subprocess

from .filesystem import trusted_file


def executable(name):
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f'required executable not found: {name}')
    return str(trusted_file(path))


def sshd_path(profile, override=None):
    if override:
        return executable(override)
    return executable('sshd.pam' if profile.name == 'alpine' else 'sshd')


def service_command(profile, override=None):
    if Path('/run/systemd/system').is_dir():
        systemctl = executable('systemctl')
        names = (override,) if override else profile.systemd_services
        for name in names:
            unit = name if name.endswith('.service') else name + '.service'
            result = subprocess.run([systemctl, 'show', '--property=LoadState', '--value', unit],
                                    capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == 'loaded':
                # A socket-activated but inactive service will reject reload; the
                # installer rolls back rather than starting it unexpectedly.
                return (systemctl, 'reload', unit)
        raise RuntimeError('no supported SSH systemd service found; specify --service')
    if profile.openrc_service and Path('/run/openrc').is_dir():
        name = override or profile.openrc_service
        if not name or any(char not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.' for char in name):
            raise RuntimeError('invalid OpenRC service name')
        return (executable('rc-service'), name, 'reload')
    raise RuntimeError('no supported running service manager; use --no-reload only for offline setup')


def check_security(profile, reviewed_selinux=False):
    enforce = Path('/sys/fs/selinux/enforce')
    if enforce.exists() and enforce.read_text().strip() == '1' and not reviewed_selinux:
        raise RuntimeError('SELinux is enforcing: an administrator-reviewed ssh-otp policy is required; '
                           'the installer does not disable SELinux or infer access from file labels. '
                           'Use --selinux-policy-reviewed only after provisioning and testing that policy.')


def restore_labels(path):
    if Path('/sys/fs/selinux/enforce').exists():
        # Apply administrator-provisioned persistent policy after atomic rename.
        # This does not create policy or grant access to the credential store.
        subprocess.run([executable('restorecon'), '-F', str(path)], check=True,
                       text=True, capture_output=True)


def check_pam_daemon(profile, daemon):
    if profile.name != 'alpine':
        return
    # OpenRC may still be running Alpine's non-PAM executable. A reload cannot
    # change that executable. Do not restart an administrator's active server.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            target = os.readlink(entry / 'exe')
        except (OSError, PermissionError):
            continue
        if Path(target).name == 'sshd' and target != daemon:
            raise RuntimeError('Alpine is running the non-PAM sshd; migrate it to sshd.pam through a trusted '
                               'session before installation. Reload alone cannot enable PAM.')
