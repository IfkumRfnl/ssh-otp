#!/usr/bin/env python3
"""Exercise production binaries and distro PAM inside a disposable rootless container."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

from integration import Issuer, require, run

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from profiles import select_profile
from profiles.runtime import sshd_path


def main():
    require(os.geteuid() == 0 and Path('/run/.containerenv').exists(), 'requires disposable Podman container')
    require(any(int(row.split()[0]) == 0 and int(row.split()[1]) != 0
                for row in Path('/proc/self/uid_map').read_text().splitlines()), 'refusing host-root identity mapping')
    os.umask(0o022)
    profile = select_profile()
    daemon_path = sshd_path(profile)
    print(f'PROFILE: {profile.name}; daemon={daemon_path}; actual distro PAM; SELinux enforcement not tested', flush=True)
    # Container-only user fixture. Production installer never creates accounts.
    home = Path('/home/hayk')
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    os.chown(home, 1000, 1000)
    for path, line in [(Path('/etc/passwd'), 'hayk:x:1000:1000:SSH OTP test:/home/hayk:/bin/sh\n'),
                       (Path('/etc/group'), 'hayk:x:1000:\n')]:
        with path.open('a') as output:
            output.write(line)
    unix_password = 'not-the-burner-password'
    hashed = run('openssl', 'passwd', '-6', '-stdin', input=unix_password+'\n').stdout.strip()
    with Path('/etc/shadow').open('a') as output:
        output.write(f'hayk:{hashed}:20000:0:99999:7:::\n')
    for directory in ('/run/sshd', '/var/empty', '/etc/ssh/sshd_config.d'):
        Path(directory).mkdir(parents=True, exist_ok=True)
    if not Path('/etc/pam.d/sshd').exists():
        raise RuntimeError('PAM-capable OpenSSH package did not install /etc/pam.d/sshd')
    original_pam = Path('/etc/pam.d/sshd').read_bytes()
    # Real distro includes must exist (e.g. authselect-generated Fedora files).
    key = Path('/root/client_key')
    run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key))
    hostkey = Path('/etc/ssh/ssh_host_ed25519_key')
    if not hostkey.exists():
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(hostkey))
    shutil.copyfile(str(key)+'.pub', '/etc/ssh/authorized_keys')
    Path('/etc/ssh/authorized_keys').chmod(0o644)
    # Network/account fixture only. Keep packaged SSH config and every PAM file.
    config = Path('/etc/ssh/sshd_config')
    packaged_config = config.read_text()
    require(any(line.strip().lower().startswith('include ') and 'sshd_config.d/' in line
                for line in packaged_config.splitlines()), 'packaged SSH config lacks a supported drop-in include')
    config.write_text('Port 22222\nListenAddress 127.0.0.1\nHostKey /etc/ssh/ssh_host_ed25519_key\n'
                      'PidFile /run/ssh-otp-test.pid\nAllowUsers hayk\nPermitRootLogin no\n'
                      'AuthorizedKeysFile /etc/ssh/authorized_keys\nStrictModes yes\nPrintMotd no\n'
                      + packaged_config)
    Path('/etc/ssh/sshd_config.d/01-smoke-key-only.conf').write_text(
        'UsePAM yes\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n')
    install_args = [sys.executable, str(ROOT / 'install.py')]
    print(run(*install_args, 'install', '--user', 'hayk', '--no-reload').stdout, end='', flush=True)
    prompt_log = Path('/root/password_prompted')
    askpass = Path('/root/askpass')
    askpass.write_text('#!/bin/sh\n: > "$SSH_OTP_TEST_PROMPT_LOG"\nprintf "%s\\n" "$SSH_OTP_TEST_PHRASE"\n')
    askpass.chmod(0o700)
    hostpub = Path(str(hostkey)+'.pub').read_text().split()
    known = Path('/root/known_hosts')
    known.write_text(f'[127.0.0.1]:22222 {hostpub[0]} {hostpub[1]}\n')
    common = ['ssh', '-F', '/dev/null', '-p', '22222', '-o', f'UserKnownHostsFile={known}',
              '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5', '-o', 'NumberOfPasswordPrompts=1',
              '-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes']
    def ssh(phrase, command='printf burner-ok', expect_prompt=True):
        prompt_log.unlink(missing_ok=True)
        env = dict(os.environ, SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE='force', DISPLAY='test',
                   SSH_OTP_TEST_PHRASE=phrase, SSH_OTP_TEST_PROMPT_LOG=str(prompt_log))
        result = subprocess.run(common + ['-o', 'PreferredAuthentications=keyboard-interactive',
            'hayk@127.0.0.1', command], stdin=subprocess.DEVNULL, capture_output=True, text=True,
            env=env, start_new_session=True, timeout=15)
        require(prompt_log.exists() == expect_prompt, 'unexpected password prompt behavior: '+result.stderr)
        return result
    with Path('/root/sshd.log').open('w+') as log:
        daemon = subprocess.Popen([daemon_path, '-D', '-e', '-f', str(config)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic()+5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', 22222), timeout=0.1):
                        break
                except OSError:
                    require(time.monotonic() < deadline and daemon.poll() is None, 'SSH daemon failed to start')
                    time.sleep(0.05)
            key_login = run(*(common + ['-o', 'PreferredAuthentications=publickey', '-i', str(key),
                                       'hayk@127.0.0.1', 'printf key-ok']), timeout=15)
            require(key_login.stdout == 'key-ok', 'key login failed')
            require(ssh('missing', expect_prompt=False).returncode != 0, 'missing burner accepted')
            ticket = Issuer(duration='3s')
            result = ssh(ticket.phrase, 'sleep 4; printf burner-ok')
            require(result.returncode == 0 and result.stdout == 'burner-ok', 'burner SSH failed: '+result.stderr)
            ticket.wait()
            require(ssh(ticket.phrase, expect_prompt=False).returncode != 0, 'replay accepted')
            ticket = Issuer()
            require(ssh(unix_password).returncode != 0, 'Unix password accepted')
            ticket.stop()
            require(ssh(ticket.phrase, expect_prompt=False).returncode != 0, 'revoked burner accepted')
            print('PASS: native key login, burner login, post-expiry session, replay/Unix-password rejection and no inactive prompt', flush=True)
        except BaseException:
            log.seek(0)
            print(log.read(), file=sys.stderr)
            raise
        finally:
            daemon.terminate()
            daemon.wait(timeout=5)
    print(run(*install_args, 'uninstall', '--no-reload').stdout, end='', flush=True)
    require(Path('/etc/pam.d/sshd').read_bytes() == original_pam, 'uninstall changed distro PAM policy')
    print('PASS: native distro PAM restored; no service manager or SELinux enforcement claims', flush=True)


if __name__ == '__main__':
    main()
