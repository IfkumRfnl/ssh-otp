#!/usr/bin/env python3
"""Build minimal disposable distro test images and verify real source-built SSH/PAM."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    'debian': ('docker.io/library/debian:trixie-slim',
               'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server openssh-client python3 gcc libc6-dev libpam-modules libpam-runtime openssl ca-certificates && rm -rf /var/lib/apt/lists/*'),
    'ubuntu': ('docker.io/library/ubuntu:24.04',
               'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server openssh-client python3 gcc libc6-dev libpam-modules libpam-runtime openssl ca-certificates && rm -rf /var/lib/apt/lists/*'),
    'fedora': ('registry.fedoraproject.org/fedora-minimal:43',
               'microdnf install -y openssh-server openssh-clients python3 gcc glibc-devel pam authselect openssl && microdnf clean all'),
    'arch': ('docker.io/library/archlinux:base',
             'pacman -Syu --noconfirm --needed openssh python gcc pam pambase openssl && pacman -Scc --noconfirm'),
    'alpine': ('docker.io/library/alpine:3.23',
               'apk add --no-cache openssh-server-pam openssh-server-common-openrc openssh-client-default linux-pam python3 build-base openssl'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('distro', choices=IMAGES)
    parser.add_argument('--zig-dir', type=Path, help='directory containing the static Zig executable and lib/')
    parser.add_argument('--rebuild', action='store_true', help='refresh base image and distro packages')
    args = parser.parse_args()
    zig = args.zig_dir
    if zig is None:
        found = shutil.which('zig')
        if not found:
            parser.error('provide --zig-dir or run under mise exec')
        zig = Path(found).resolve().parent
    if not (zig / 'zig').is_file() or not (zig / 'lib').is_dir():
        parser.error('--zig-dir must contain zig and lib/')
    podman = shutil.which('podman')
    if not podman:
        parser.error('rootless podman is required; no Docker daemon is used')
    command = [podman, '--cgroup-manager=cgroupfs']
    tag = f'localhost/ssh-otp-test-{args.distro}'
    image, packages = IMAGES[args.distro]
    print(f'Preparing minimal {args.distro} image; no init system will be booted.', flush=True)
    exists = subprocess.run(command + ['image', 'exists', tag]).returncode == 0
    if args.rebuild or not exists:
        with tempfile.TemporaryDirectory(prefix='ssh-otp-container-build-') as directory:
            recipe = Path(directory) / 'Containerfile'
            recipe.write_text(f'FROM {image}\nRUN {packages}\n')
            subprocess.run(command + ['build', '--pull=always', '-t', tag, '-f', str(recipe), directory], check=True)
    print(f'Running {args.distro} source build and SSH/PAM smoke test on private loopback.', flush=True)
    # No privileges, host networking, published ports or writable source mounts.
    # Container namespace root owns only its disposable writable filesystem.
    script = '''set -eu
mkdir -p /work
cp -R /src/src /src/profiles /src/tests /src/build.zig /src/install.py /src/ssh-otp.1 /work/
cd /work
/opt/zig/zig build -j2 -Doptimize=ReleaseSafe --summary all
/opt/zig/zig build test -j2 -Doptimize=ReleaseSafe --summary all
python3 -m unittest discover -s tests -p test_filesystem.py -v
python3 tests/distro_smoke.py
'''
    subprocess.run(command + ['run', '--rm', '--network=none', '--name', f'ssh-otp-test-{args.distro}',
        '-v', f'{ROOT}:/src:ro', '-v', f'{zig.resolve()}:/opt/zig:ro',
        '-v', f'ssh-otp-zig-cache-{args.distro}:/root/.cache/zig',
        '-v', f'ssh-otp-build-cache-{args.distro}:/work/.zig-cache', tag,
        '/bin/sh', '-c', script], check=True)
    print(f'PASS: {args.distro} source build, unit tests and native SSH/PAM smoke', flush=True)


if __name__ == '__main__':
    main()
