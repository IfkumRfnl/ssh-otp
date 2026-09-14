"""Machine-specific SSH discovery; never start services or weaken SELinux."""
from functools import partial
from pathlib import Path
import os
import shutil
import signal
import subprocess

from .filesystem import trusted_file


def executable(name):
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f'required executable not found: {name}')
    trusted_file(path)
    # Multicall tools such as restorecon select their behavior from argv[0].
    return str(Path(path).absolute())


def sshd_path(profile, override=None):
    if override:
        return executable(override)
    return executable('sshd.pam' if profile.name == 'alpine' else 'sshd')


def service_reloader(profile, daemon, override=None, pidfile=None):
    if pidfile is not None:
        pidfile = Path(pidfile)
        if not pidfile.is_absolute():
            raise RuntimeError('OpenRC pidfile must be an absolute path')
    if Path('/run/systemd/system').is_dir():
        if pidfile is not None:
            raise RuntimeError('--pidfile is only supported for OpenRC services')
        systemctl = executable('systemctl')
        names = (override,) if override else profile.systemd_services
        for name in names:
            unit = name if name.endswith('.service') else name + '.service'
            result = subprocess.run([systemctl, 'show', '--property=LoadState', '--value', unit],
                                    capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == 'loaded':
                # A socket-activated but inactive service will reject reload; the
                # installer rolls back rather than starting it unexpectedly.
                return partial(subprocess.run, [systemctl, 'reload', unit],
                               check=True, capture_output=True, text=True)
        raise RuntimeError('no supported SSH systemd service found; specify --service')
    if profile.openrc_service and Path('/run/openrc').is_dir():
        name = override or profile.openrc_service
        if not name or any(char not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.' for char in name):
            raise RuntimeError('invalid OpenRC service name')
        if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
            raise RuntimeError('OpenRC reload requires Python pidfd support; use --no-reload')
        # Read the pidfile on every reload, including rollback. Alpine's packaged
        # reload reselects the executable from UsePAM, which uninstall removes.
        return partial(_reload_openrc, pidfile if pidfile is not None else Path(f'/run/{name}.pid'), daemon)
    raise RuntimeError('no supported running service manager; use --no-reload only for offline setup')


def _reload_openrc(pidfile, daemon):
    pid = int(trusted_file(pidfile).read_text().strip())
    if pid <= 1:
        raise RuntimeError(f'invalid SSH daemon PID in {pidfile}')
    # Pin the process before checking its executable. If it exits and the PID
    # is reused, pidfd_send_signal fails instead of signaling the replacement.
    fd = os.pidfd_open(pid)
    try:
        if not os.path.samefile(f'/proc/{pid}/exe', daemon):
            raise RuntimeError(f'SSH pidfile does not identify the selected daemon: {pidfile}')
        signal.pidfd_send_signal(fd, signal.SIGHUP)
    finally:
        os.close(fd)


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
        # Linux marks unlinked executables this way after package replacement.
        target = target.removesuffix(' (deleted)')
        if Path(target).name == 'sshd' and target != daemon:
            raise RuntimeError('Alpine is running the non-PAM sshd; migrate it to sshd.pam through a trusted '
                               'session before installation. Reload alone cannot enable PAM.')
