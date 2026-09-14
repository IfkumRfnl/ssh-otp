#!/usr/bin/env python3
"""Run under unshare --user --map-auto --map-root-user --mount --net.
Exercises production binaries, setuid authorization and real OpenSSH/PAM.
Never run directly as host root: namespace and mount checks are mandatory.
"""
import concurrent.futures
import os
from pathlib import Path
import pty
import pwd
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr}')
    return result


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def put(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)


class Issuer:
    def __init__(self, user='hayk', duration='30s', caller=1000):
        self.fd, slave = pty.openpty()
        self.output = b''
        self.process = subprocess.Popen(['/usr/local/bin/ssh-otp', user, duration],
            stdin=slave, stdout=slave, stderr=slave,
            user=caller, group=caller, extra_groups=[])
        os.close(slave)
        self.phrase = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.drain()
            match = re.search(rb'([a-z-]+(?:=[a-z-]+){3})\r?\n', self.output)
            if match:
                self.phrase = match[1].decode()
                return
            if self.process.poll() is not None:
                break
        raise AssertionError('issuer failed: ' + self.output.decode())

    def drain(self):
        if select.select([self.fd], [], [], 0.05)[0]:
            try:
                self.output += os.read(self.fd, 4096)
            except OSError:
                pass

    def wait(self):
        result = self.process.wait(timeout=5)
        self.drain()
        os.close(self.fd)
        return result

    def stop(self, sig=signal.SIGINT):
        self.process.send_signal(sig)
        return self.wait()


def main():
    os.umask(0o022)
    require(os.geteuid() == 0, 'requires namespace root')
    mappings = Path('/proc/self/uid_map').read_text().splitlines()
    require(any(int(line.split()[0]) == 0 and int(line.split()[1]) != 0 for line in mappings),
            'REFUSING host root or identity UID mapping')
    # Mapped root has no capabilities in the host mount/network namespaces.
    # These operations fail unless unshare created namespaces owned by this userns.
    run('mount', '--make-rprivate', '/')
    if '--inside' not in sys.argv:
        # A user namespace maps host-owned system directories to nobody. Use a
        # minimal chroot with root-owned installation parents, not weaker checks.
        jail = Path(tempfile.mkdtemp(prefix='ssh-otp-rootfs-'))
        jail.chmod(0o755)
        run('mount', '--bind', str(jail), str(jail))
        try:
            for relative in ('usr/bin', 'usr/sbin', 'usr/lib', 'usr/lib64', 'usr/libexec', 'usr/include',
                             'usr/local', 'etc', 'run', 'var/lib', 'proc', 'dev', 'project', 'tmp'):
                (jail / relative).mkdir(parents=True, exist_ok=True)
            (jail / 'tmp').chmod(0o1777)
            for name, target in (('bin', 'usr/bin'), ('sbin', 'usr/sbin'), ('lib', 'usr/lib'), ('lib64', 'usr/lib64')):
                (jail / name).symlink_to(target)
            for source in ('/usr/bin', '/usr/sbin', '/usr/lib', '/usr/lib64', '/usr/libexec', '/usr/include', '/proc', '/dev'):
                run('mount', '--rbind', source, str(jail / source.lstrip('/')))
            run('mount', '--bind', str(ROOT), str(jail / 'project'))
            return subprocess.run(['chroot', str(jail), '/usr/bin/python3',
                                   '/project/tests/integration.py', '--inside']).returncode
        finally:
            # Never traverse bind-mounted host files with rmtree.
            run('umount', '--lazy', str(jail))
            shutil.rmtree(jail)
    with tempfile.TemporaryDirectory(prefix='ssh-otp-integration-') as directory:
        base = Path(directory)
        base.chmod(0o755)
        etc = base / 'etc'
        etc.mkdir()
        home = base / 'home'
        home.mkdir(mode=0o700)
        os.chown(home, 1000, 1000)
        put(etc / 'passwd', f'root:x:0:0:root:/root:/bin/sh\nhayk:x:1000:1000:Test:{home}:/bin/sh\nsshd:x:102:102:sshd:/run/sshd:/usr/sbin/nologin\n')
        put(etc / 'group', 'root:x:0:\nhayk:x:1000:\nsshd:x:102:\n')
        unix_password = 'not-the-burner-password'
        hashed = run('openssl', 'passwd', '-6', '-stdin', input=unix_password+'\n').stdout.strip()
        put(etc / 'shadow', f'root:{hashed}:20000:0:99999:7:::\nhayk:{hashed}:20000:0:99999:7:::\nsshd:!:20000:0:99999:7:::\n', 0o600)
        put(etc / 'nsswitch.conf', 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n')
        put(etc / 'pam.d/sshd', '@include common-auth\n@include common-account\n@include common-session\n@include common-password\n')
        for stack, line in {'auth': 'auth required pam_unix.so', 'account': 'account required pam_unix.so',
                            'session': 'session required pam_permit.so', 'password': 'password required pam_unix.so'}.items():
            put(etc / f'pam.d/common-{stack}', line+'\n')
        run('mount', '--bind', str(etc), '/etc')
        key = base / 'client_key'
        hostkey = etc / 'ssh/ssh_host_ed25519_key'
        hostkey.parent.mkdir()
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key))
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(hostkey))
        authorized = Path('/etc/ssh/authorized_keys')
        shutil.copyfile(str(key)+'.pub', authorized)
        authorized.chmod(0o644)
        (etc / 'ssh/sshd_config.d').mkdir()
        put(etc / 'ssh/sshd_config', f'''Include /etc/ssh/sshd_config.d/*.conf
Port 22222
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/ssh-otp-test-sshd.pid
UsePAM yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers hayk
AuthorizedKeysFile {authorized}
StrictModes yes
MaxAuthTries 3
PrintMotd no
''')
        run('mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run')
        Path('/run/sshd').mkdir(mode=0o755)
        # A fresh userns-owned filesystem permits namespace-local setuid; bind
        # mounts of host filesystems deliberately suppress that transition.
        run('mount', '-t', 'tmpfs', '-o', 'mode=755,suid', 'tmpfs', '/usr/local')
        for relative in ('bin', 'lib/security', 'share/man/man1'):
            (Path('/usr/local') / relative).mkdir(parents=True, exist_ok=True)
        Path('/usr/local/sbin').mkdir()
        shutil.copyfile('/usr/sbin/sshd', '/usr/local/sbin/sshd')
        Path('/usr/local/sbin/sshd').chmod(0o755)
        # Isolate install backups as well as configuration and binaries.
        run('mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/var/lib')
        run('ip', 'link', 'set', 'lo', 'up')
        python = sys.executable
        installed = run(python, str(ROOT / 'install.py'), 'install', '--user', 'hayk', '--no-reload',
                        '--profile', 'debian', '--sshd-path', '/usr/local/sbin/sshd')
        require('Installed.' in installed.stdout, 'installation failed')
        print('PASS: installer config validation and setuid installation', flush=True)
        for target, expected in [('root', 'only root'), ('ssh-otp-nonexistent-user', 'does not exist')]:
            denied = subprocess.run(['/usr/local/bin/ssh-otp', target, '30s'], user=1000, group=1000,
                                    extra_groups=[], capture_output=True, text=True)
            require(denied.returncode != 0 and expected in denied.stderr, 'issuance authorization failed')
        piped = subprocess.run(['/usr/local/bin/ssh-otp', 'hayk', '30s'], user=1000, group=1000,
                               extra_groups=[], capture_output=True, text=True)
        require(piped.returncode != 0 and 'terminal' in piped.stderr, 'redirection check failed: '+piped.stderr)
        for duration in ('0s', '61m', '-1s', '10', '999999999999999h'):
            invalid = subprocess.run(['/usr/local/bin/ssh-otp', 'hayk', duration], capture_output=True)
            require(invalid.returncode != 0, 'invalid duration accepted')
        print('PASS: real-UID authorization, unknown users, duration bounds, secret redirection', flush=True)
        # Exercise the real system PAM loader for simultaneous attempts without SSH startup timing.
        harness = base / 'pam_harness'
        run('gcc', '-O2', '-Wall', '-Wextra', '-Werror', str(ROOT / 'tests/pam_harness.c'), '-ldl', '-o', str(harness))
        def pam(phrase):
            return subprocess.run([str(harness), '/etc/pam.d', 'sshd', 'hayk', '-'],
                                  input=phrase+'\n', text=True, capture_output=True).returncode
        ticket = Issuer()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(pam, [ticket.phrase, ticket.phrase]))
        require(sorted(results) == [0, 7], f'atomic consumption failed: {results}')
        require(ticket.wait() == 0, 'issuer did not observe consumption')
        ticket = Issuer()
        for _ in range(5):
            require(pam('wrong') != 0, 'wrong passphrase accepted')
        require(pam(ticket.phrase) != 0, 'attempt cap failed')
        ticket.wait()
        old = Issuer()
        new = Issuer(caller=0)
        old.wait()
        require(pam(old.phrase) != 0 and pam(new.phrase) == 0, 'replacement or stale cleanup failed')
        new.wait()
        cancelled = Issuer()
        require(cancelled.stop() == 130 and pam(cancelled.phrase) != 0, 'Ctrl-C revocation failed')
        expired = Issuer(duration='1s')
        require(expired.wait() == 0 and pam(expired.phrase) != 0, 'expiry failed')
        killed = Issuer(duration='2s')
        killed.stop(signal.SIGKILL)
        time.sleep(2.1)
        require(pam(killed.phrase) != 0, 'expiry depends on issuer survival')
        print('PASS: real PAM consumption race, retry cap, replacement, Ctrl-C, expiry, killed issuer', flush=True)
        # Pin the generated host key rather than disabling host verification.
        hostpub = Path(str(hostkey)+'.pub').read_text().split()
        known = base / 'known_hosts'
        put(known, f'[127.0.0.1]:22222 {hostpub[0]} {hostpub[1]}\n')
        askpass = base / 'askpass'
        prompt_log = base / 'password_prompted'
        put(askpass, '#!/bin/sh\n: > "$SSH_OTP_TEST_PROMPT_LOG"\nprintf "%s\\n" "$SSH_OTP_TEST_PHRASE"\n', 0o755)
        common = ['ssh', '-F', '/dev/null', '-p', '22222', '-o', f'UserKnownHostsFile={known}',
                  '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5', '-o', 'NumberOfPasswordPrompts=1',
                  '-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes']
        def ssh(phrase, command='printf burner-ok', expect_prompt=True):
            prompt_log.unlink(missing_ok=True)
            env = dict(os.environ, SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE='force', DISPLAY='test',
                       SSH_OTP_TEST_PHRASE=phrase, SSH_OTP_TEST_PROMPT_LOG=str(prompt_log))
            result = subprocess.run(common + ['-o', 'PreferredAuthentications=keyboard-interactive',
                'hayk@127.0.0.1', command], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                env=env, start_new_session=True, timeout=10)
            require(prompt_log.exists() == expect_prompt, 'unexpected SSH password prompt behavior')
            return result
        log = open(base / 'sshd.log', 'w+')
        daemon = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', '/etc/ssh/sshd_config'], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', 22222), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline or daemon.poll() is not None:
                        log.seek(0)
                        raise AssertionError('sshd failed: ' + log.read())
                    time.sleep(0.05)
            key_login = run(*(common + ['-o', 'PreferredAuthentications=publickey', '-i', str(key),
                                      'hayk@127.0.0.1', 'printf key-ok']), timeout=10)
            require(key_login.stdout == 'key-ok', 'key access changed')
            require(ssh('no-burner', expect_prompt=False).returncode != 0,
                    'SSH accepted connection without an active burner')
            ticket = Issuer(duration='2s')
            login = ssh(ticket.phrase, 'sleep 3; printf burner-ok')
            require(login.returncode == 0 and login.stdout == 'burner-ok', 'SSH burner login failed: '+login.stderr)
            ticket.wait()
            require(ssh(ticket.phrase, expect_prompt=False).returncode != 0, 'SSH replay accepted')
            ticket = Issuer()
            require(ssh(unix_password).returncode != 0, 'Unix password accepted as burner')
            ticket.stop()
            require(ssh(ticket.phrase, expect_prompt=False).returncode != 0, 'revoked burner accepted')
            expired = Issuer(duration='1s')
            expired.stop(signal.SIGKILL)
            time.sleep(1.1)
            require(ssh(expired.phrase, expect_prompt=False).returncode != 0, 'expired burner prompted or accepted')
            print('PASS: no SSH password prompt for missing, consumed, revoked or expired burners', flush=True)
            print('PASS: real SSH key login, burner login, session survives deadline, replay and Unix-password rejection', flush=True)
        except BaseException:
            log.seek(0)
            print(log.read(), file=sys.stderr)
            raise
        finally:
            daemon.terminate()
            daemon.wait(timeout=5)
            log.close()
        removed = run(python, str(ROOT / 'install.py'), 'uninstall', '--no-reload',
                      '--profile', 'debian', '--sshd-path', '/usr/local/sbin/sshd')
        require('Uninstalled' in removed.stdout and not Path('/usr/local/bin/ssh-otp').exists(), 'uninstall failed')
        require('@include common-auth' in Path('/etc/pam.d/sshd').read_text(), 'original PAM not restored')
        print('PASS: uninstall restores original authentication configuration', flush=True)
        put(Path('/etc/ssh/sshd_config.d/00-conflict.conf'), 'KbdInteractiveAuthentication no\n')
        conflict = subprocess.run([python, str(ROOT / 'install.py'), 'install', '--user', 'hayk', '--no-reload',
                                   '--profile', 'debian', '--sshd-path', '/usr/local/sbin/sshd'],
                                  capture_output=True, text=True)
        require(conflict.returncode != 0 and 'configuration conflict' in conflict.stderr,
                'installer accepted conflicting effective SSH configuration')
        require(not Path('/usr/local/bin/ssh-otp').exists() and not Path('/var/lib/ssh-otp-install').exists(),
                'failed installation left privileged artifacts or state')
        require('@include common-auth' in Path('/etc/pam.d/sshd').read_text(),
                'failed installation did not restore original authentication')
        print('PASS: configuration conflict rolls installation back', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
