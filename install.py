#!/usr/bin/env python3
"""Install/uninstall ssh-otp on Debian. Build as your normal user first."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

STATE = Path('/var/lib/ssh-otp-install')
PAM = Path('/etc/pam.d/sshd')
DROPIN = Path('/etc/ssh/sshd_config.d/00-ssh-otp.conf')
CLI = Path('/usr/local/bin/ssh-otp')
MODULE = Path('/usr/local/lib/security/pam_ssh_otp.so')
MAN = Path('/usr/local/share/man/man1/ssh-otp.1')
SSHD = '/usr/sbin/sshd'
CONFIG = b'''# Managed by ssh-otp. Account restrictions remain in sshd_config.
UsePAM yes
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication yes
AuthenticationMethods publickey keyboard-interactive:pam
'''


def command(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_parent(path):
    for directory in [*reversed(path.parent.parents), path.parent]:
        if not directory.exists() and not directory.is_symlink():
            directory.mkdir(mode=0o755)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError(f'unsafe installation directory: {directory}')


def replace(path, data, mode=0o644):
    safe_parent(path)
    fd, temporary = tempfile.mkstemp(prefix='.ssh-otp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            os.fchown(output.fileno(), 0, 0)
            os.fchmod(output.fileno(), mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def validate(user):
    command(SSHD, '-t')
    output = command(SSHD, '-T', '-C', f'user={user},host=localhost,addr=127.0.0.1')
    settings = dict(line.split(' ', 1) for line in output.splitlines())
    expected = {'usepam': 'yes', 'pubkeyauthentication': 'yes',
                'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'yes',
                'authenticationmethods': 'publickey keyboard-interactive:pam'}
    for key, value in expected.items():
        if settings.get(key) != value:
            raise RuntimeError(f'effective {key}={settings.get(key)!r}; expected {value!r}; configuration conflict')


def reload_ssh(no_reload):
    if not no_reload:
        command('/usr/bin/systemctl', 'reload', 'ssh')


def install(args):
    import pwd
    pwd.getpwnam(args.user)
    if STATE.exists():
        raise RuntimeError('already installed or an interrupted install exists; inspect /var/lib/ssh-otp-install before proceeding')
    original = PAM.read_bytes()
    lines = original.decode().splitlines(keepends=True)
    auth = [line for line in lines if line.strip() == '@include common-auth']
    if len(auth) != 1 or any(line.lstrip().startswith(('auth ', 'auth\t', '-auth ', '-auth\t')) for line in lines):
        raise RuntimeError('unsupported PAM auth stack: expected exactly one @include common-auth and no other auth rules')
    allowed = {'@include common-auth', '@include common-account', '@include common-session', '@include common-password'}
    if any(line.lstrip().startswith('@include') and line.strip() not in allowed for line in lines):
        raise RuntimeError('unsupported PAM include; review it manually before installing')
    # Included account/session/password stacks must not introduce another auth rule.
    for include in ('common-account', 'common-session', 'common-password'):
        for line in (PAM.parent / include).read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith(('auth ', 'auth\t', '-auth ', '-auth\t', '@include')):
                raise RuntimeError(f'unsupported authentication/nested include in {include}')
    effective = command(SSHD, '-T', '-C', f'user={args.user},host=localhost,addr=127.0.0.1')
    settings = dict(line.split(' ', 1) for line in effective.splitlines())
    if settings.get('authenticationmethods') not in ('any', 'publickey'):
        raise RuntimeError('refusing to replace an existing multi-factor/custom AuthenticationMethods policy')
    if settings.get('passwordauthentication') != 'no' or settings.get('kbdinteractiveauthentication') != 'no':
        raise RuntimeError('expected key-only SSH configuration; refusing to remove existing password/MFA access implicitly')
    root = Path(__file__).resolve().parent
    artifacts = {CLI: ((root / 'zig-out/bin/ssh-otp').read_bytes(), 0o4755),
                 MODULE: ((root / 'zig-out/lib/libpam_ssh_otp.so').read_bytes(), 0o644),
                 MAN: ((root / 'ssh-otp.1').read_bytes(), 0o644),
                 DROPIN: (CONFIG, 0o644)}
    for path in artifacts:
        if path.exists() or path.is_symlink():
            raise RuntimeError(f'refusing to overwrite untracked file: {path}')
    for binary in (CLI, MODULE):
        if not artifacts[binary][0].startswith(b'\x7fELF'):
            raise RuntimeError(f'not an ELF binary: {binary}')
    patched = ''.join(f'auth requisite {MODULE}\n' if line.strip() == '@include common-auth' else line for line in lines).encode()
    safe_parent(STATE)
    STATE.mkdir(mode=0o700)
    replace(STATE / 'sshd.pam.original', original, 0o600)
    manifest = {'pam_sha256': digest(patched), 'files': {str(path): digest(data) for path, (data, _) in artifacts.items()}}
    replace(STATE / 'manifest.json', json.dumps(manifest).encode(), 0o600)
    written = []
    try:
        for path, (data, mode) in artifacts.items():
            replace(path, data, mode)
            written.append(path)
        replace(PAM, patched)
        validate(args.user)
        reload_ssh(args.no_reload)
    except BaseException:
        replace(PAM, original)
        for path in reversed(written):
            path.unlink(missing_ok=True)
        shutil.rmtree(STATE)
        if not args.no_reload:
            try:
                command(SSHD, '-t')
                reload_ssh(False)
            except Exception as error:
                print(f'Rollback restored files, but SSH reload failed: {error}', file=sys.stderr)
        raise
    print('Installed. Existing SSH account restrictions and sudo policy are unchanged.')
    if args.no_reload:
        print('SSH was NOT reloaded. Run sudo systemctl reload ssh when ready.')
    print(f'Keep your trusted session open. Run: ssh-otp {args.user} 10m')


def uninstall(args):
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError('unsafe installation state directory')
    manifest = json.loads((STATE / 'manifest.json').read_text())
    files = manifest['files']
    if set(files) != {str(path) for path in (CLI, MODULE, MAN, DROPIN)}:
        raise RuntimeError('unexpected installation manifest')
    if digest(PAM.read_bytes()) != manifest['pam_sha256']:
        raise RuntimeError('PAM configuration changed since installation; refusing to overwrite it')
    for name, expected in files.items():
        path = Path(name)
        if path.is_symlink() or digest(path.read_bytes()) != expected:
            raise RuntimeError(f'installed file changed: {path}; refusing automatic removal')
    installed_pam = PAM.read_bytes()
    installed_dropin = DROPIN.read_bytes()
    replace(PAM, (STATE / 'sshd.pam.original').read_bytes())
    DROPIN.unlink()
    try:
        command(SSHD, '-t')
        reload_ssh(args.no_reload)
    except BaseException:
        replace(PAM, installed_pam)
        replace(DROPIN, installed_dropin)
        raise
    # Keep the PAM module mapped for existing processes, but remove it on disk.
    for path in (CLI, MODULE, MAN):
        path.unlink()
    runtime = Path('/run/ssh-otp')
    if runtime.exists():
        info = runtime.lstat()
        if stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700:
            shutil.rmtree(runtime)
    shutil.rmtree(STATE)
    print('Uninstalled; original SSH PAM authentication restored.')
    if args.no_reload:
        print('SSH was NOT reloaded. Run sudo systemctl reload ssh when ready.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'uninstall'))
    parser.add_argument('--user', default='hayk', help='existing account used to validate effective SSH settings')
    parser.add_argument('--no-reload', action='store_true', help='validate configuration without reloading SSH')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('installation requires root; build first, then use sudo python3 install.py')
    try:
        (install if args.action == 'install' else uninstall)(args)
    except (OSError, RuntimeError, KeyError, subprocess.CalledProcessError) as error:
        print(f'Installation failed: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
