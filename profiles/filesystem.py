"""Root-controlled path handling, including distro-managed directory symlinks."""
from collections import deque
import os
from pathlib import Path
import stat


def safe_parent(path, *, create=True):
    # Validate every component before following symlinks. Resolving first could
    # hide an attacker-writable intermediate directory from these checks.
    pending = deque(path.absolute().parent.parts[1:])
    directory = Path('/')
    root = directory.stat()
    if root.st_uid != 0 or root.st_mode & 0o022:
        raise RuntimeError('unsafe installation directory: /')
    links = 0
    while pending:
        part = pending.popleft()
        if part == '..':
            directory = directory.parent
            continue
        candidate = directory / part
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            if not create:
                raise
            candidate.mkdir(mode=0o755)
            info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode):
            links += 1
            if info.st_uid != 0 or links > 40:
                raise RuntimeError(f'unsafe installation symlink: {candidate}')
            target = Path(os.readlink(candidate))
            if target.is_absolute():
                directory = Path('/')
                components = target.parts[1:]
            else:
                components = target.parts
            pending.extendleft(reversed(components))
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError(f'unsafe installation directory: {candidate}')
        directory = candidate


def trusted_file(path):
    path = Path(path).absolute()
    for _ in range(40):
        safe_parent(path, create=False)
        info = path.lstat()
        if info.st_uid != 0:
            raise RuntimeError(f'unsafe file owner: {path}')
        if stat.S_ISLNK(info.st_mode):
            target = Path(os.readlink(path))
            path = target if target.is_absolute() else path.parent / target
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise RuntimeError(f'unsafe file permissions or type: {path}')
        return path.resolve(strict=True)
    raise RuntimeError(f'recursive file symlink: {path}')
