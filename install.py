#!/usr/bin/env python3
"""Install/uninstall ssh-otp on Debian. Build as your normal user first."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile

RUNTIME = Path('/run/ssh-otp')
STATE = Path('/var/lib/ssh-otp-install')
PAM = Path('/etc/pam.d/sshd')
DROPIN = Path('/etc/ssh/sshd_config.d/00-ssh-otp.conf')
CLI = Path('/usr/local/bin/ssh-otp')
MODULE = Path('/usr/local/lib/security/pam_ssh_otp.so')
MAN = Path('/usr/local/share/man/man1/ssh-otp.1')
SSHD = '/usr/sbin/sshd'
FILE_MODES = {CLI: 0o4755, MODULE: 0o644, MAN: 0o644, DROPIN: 0o644}
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


def read_owned_file(path, mode):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != mode):
        raise RuntimeError(f'unsafe file ownership, permissions or type: {path}')
    return path.read_bytes()


def recover(errors, description, operation, *args, **kwargs):
    """Attempt an independent recovery step without hiding the original error."""
    try:
        operation(*args, **kwargs)
        return True
    except Exception as error:
        errors.append(f'{description}: {error}')
        return False


def report_recovery(errors):
    for error in errors:
        print(f'Recovery failed: {error}', file=sys.stderr)
    if errors:
        print(f'Keep your trusted session open; inspect recovery files in {STATE}.', file=sys.stderr)


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
            os.fchown(output.fileno(), 0, 0)
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
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
    try:
        pwd.getpwnam(args.user)
    except KeyError:
        raise RuntimeError(f'unknown user: {args.user}') from None
    if STATE.exists() or STATE.is_symlink():
        raise RuntimeError(f'already installed or an interrupted install exists; inspect {STATE} before proceeding')
    original = read_owned_file(PAM, 0o644)
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
    artifacts = {
        CLI: (root / 'zig-out/bin/ssh-otp').read_bytes(),
        MODULE: (root / 'zig-out/lib/libpam_ssh_otp.so').read_bytes(),
        MAN: (root / 'ssh-otp.1').read_bytes(),
        DROPIN: CONFIG,
    }
    for path in artifacts:
        if path.exists() or path.is_symlink():
            raise RuntimeError(f'refusing to overwrite untracked file: {path}')
    for binary in (CLI, MODULE):
        if not artifacts[binary].startswith(b'\x7fELF'):
            raise RuntimeError(f'not an ELF binary: {binary}')
    for index, line in enumerate(lines):
        if line.strip() == '@include common-auth':
            lines[index] = f'auth requisite {MODULE}\n'
    patched = ''.join(lines).encode()
    manifest = {'pam_sha256': digest(patched), 'files': {}}
    for path, data in artifacts.items():
        manifest['files'][str(path)] = digest(data)

    state_created = False
    pam_touched = False
    reload_started = False
    written = []
    try:
        safe_parent(STATE)
        STATE.mkdir(mode=0o700)
        state_created = True
        replace(STATE / 'sshd.pam.original', original, 0o600)
        replace(STATE / 'manifest.json', json.dumps(manifest).encode(), 0o600)
        for path, data in artifacts.items():
            written.append(path)
            replace(path, data, FILE_MODES[path])
        pam_touched = True
        replace(PAM, patched)
        validate(args.user)
        reload_started = not args.no_reload
        reload_ssh(args.no_reload)
    except BaseException:
        errors = []
        pam_restored = not pam_touched or recover(errors, 'restore PAM', replace, PAM, original)
        for path in reversed(written):
            # Never remove a module that the still-installed PAM stack requires.
            if path == MODULE and not pam_restored:
                continue
            recover(errors, f'remove {path}', path.unlink, missing_ok=True)
        if reload_started:
            valid = recover(errors, 'validate restored SSH configuration', command, SSHD, '-t')
            if valid:
                recover(errors, 'reload restored SSH configuration', reload_ssh, False)
        if state_created and not errors:
            recover(errors, 'remove installation state', shutil.rmtree, STATE)
        report_recovery(errors)
        raise
    print('Installed. Existing SSH account restrictions and sudo policy are unchanged.')
    if args.no_reload:
        print('SSH was NOT reloaded. Run sudo systemctl reload ssh when ready.')
    print(f'Keep your trusted session open. Run: ssh-otp {args.user} 10m')


def uninstall(args):
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError('unsafe installation state directory')
    manifest_data = read_owned_file(STATE / 'manifest.json', 0o600)
    manifest = json.loads(manifest_data)
    if not isinstance(manifest, dict):
        raise RuntimeError('invalid installation manifest: expected an object')
    files = manifest.get('files')
    if not isinstance(files, dict) or set(files) != {str(path) for path in FILE_MODES}:
        raise RuntimeError('unexpected installation manifest files')
    hashes = [manifest.get('pam_sha256'), *files.values()]
    if any(not isinstance(value, str) or len(value) != 64
           or any(char not in '0123456789abcdef' for char in value) for value in hashes):
        raise RuntimeError('invalid installation manifest hashes')
    installed_pam = read_owned_file(PAM, 0o644)
    if digest(installed_pam) != manifest['pam_sha256']:
        raise RuntimeError('PAM configuration changed since installation; refusing to overwrite it')
    installed = {}
    for path, mode in FILE_MODES.items():
        data = read_owned_file(path, mode)
        if digest(data) != files[str(path)]:
            raise RuntimeError(f'installed file changed: {path}; refusing automatic removal')
        installed[path] = data
    original = read_owned_file(STATE / 'sshd.pam.original', 0o600)
    runtime = RUNTIME
    if runtime.exists() or runtime.is_symlink():
        info = runtime.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError(f'unsafe runtime directory: {runtime}')
    try:
        DROPIN.unlink()
        command(SSHD, '-t')
        reload_ssh(args.no_reload)
        replace(PAM, original)
        # Mapped modules remain available to processes that already loaded them.
        for path in (CLI, MODULE, MAN):
            path.unlink()
        if runtime.exists():
            shutil.rmtree(runtime)
        shutil.rmtree(STATE)
    except BaseException:
        errors = []
        # Restore burner-only PAM before re-enabling its SSH authentication path.
        # Even a missing module must fail closed, not fall back to common-auth.
        for path, data in installed.items():
            if path != DROPIN:
                recover(errors, f'restore {path}', replace, path, data, FILE_MODES[path])
        pam_restored = recover(errors, 'restore installed PAM', replace, PAM, installed_pam)
        if pam_restored:
            recover(errors, 'restore SSH drop-in', replace, DROPIN, installed[DROPIN])
        else:
            recover(errors, 'disable SSH drop-in', DROPIN.unlink, missing_ok=True)
        recover(errors, 'restore recovery directory', STATE.mkdir, mode=0o700, exist_ok=True)
        recover(errors, 'restore original PAM backup', replace, STATE / 'sshd.pam.original', original, 0o600)
        recover(errors, 'restore manifest', replace, STATE / 'manifest.json', manifest_data, 0o600)
        if not args.no_reload:
            valid = recover(errors, 'validate restored SSH configuration', command, SSHD, '-t')
            if valid:
                recover(errors, 'reload restored SSH configuration', reload_ssh, False)
        report_recovery(errors)
        raise
    print('Uninstalled; original SSH PAM authentication restored.')
    if args.no_reload:
        print('SSH was NOT reloaded. Run sudo systemctl reload ssh when ready.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'uninstall'))
    parser.add_argument('--user', help='existing account used to validate effective SSH settings; required for install')
    parser.add_argument('--no-reload', action='store_true', help='validate configuration without reloading SSH')
    args = parser.parse_args()
    if args.action == 'install' and not args.user:
        parser.error('--user is required for install')
    if os.geteuid() != 0:
        parser.error('installation requires root; build first, then use sudo python3 install.py')
    try:
        if args.action == 'install':
            install(args)
        else:
            uninstall(args)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f'{args.action.capitalize()} failed: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
