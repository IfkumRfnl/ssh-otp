"""Audited PAM transformations shared by Linux distribution profiles."""
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Profile:
    name: str
    os_ids: tuple[str, ...]
    id_like: tuple[str, ...]
    systemd_services: tuple[str, ...]
    openrc_service: str | None
    auth_includes: tuple[str, ...]
    retained_auth_modules: tuple[str, ...] = ()
    retained_auth_includes: tuple[str, ...] = ()
    packages: tuple[str, ...] = ()
    selinux: bool = False


# These implement the old password branch, not independent authorization gates.
PASSWORD_MODULES = frozenset({'pam_unix.so', 'pam_sss.so', 'pam_systemd_home.so'})
BRANCH_MODULES = frozenset({'pam_deny.so', 'pam_permit.so'})
RULE = re.compile(r'^(-?(?:auth|account|password|session))\s+(\[[^\]]+\]|\S+)\s+(\S+)(?:\s+(.*))?$')
NAME = re.compile(r'^[a-zA-Z0-9_-]+$')


def patch_pam(text, module_path, profile, read_include):
    """Replace password authentication while retaining audited authorization gates.

    Numeric PAM jumps belonging to the discarded password branch are discarded
    with it. Retained gates must not jump over the replacement authentication.
    Includes are expanded only for their auth rules; other management groups in
    the root service remain byte-for-byte unchanged.
    """
    if not module_path.startswith('/') or any(char.isspace() for char in module_path):
        raise RuntimeError('PAM module must have an absolute path without whitespace')
    inserted = False
    credentials = 0
    cache = {}

    def included(name, chain):
        if not NAME.fullmatch(name) or name in chain or len(chain) >= 16:
            raise RuntimeError(f'unsafe or recursive PAM include: {name}')
        if name not in cache:
            cache[name] = read_include(name)
        return cache[name]

    def rule(line):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            return None
        if '\\' in stripped:
            raise RuntimeError('unsupported PAM continuation or escaping')
        if stripped.startswith('@include '):
            name = stripped.split('#', 1)[0].split()
            if len(name) != 2:
                raise RuntimeError('invalid PAM include')
            return ('@include', '', name[1], '')
        match = RULE.fullmatch(stripped)
        if not match:
            raise RuntimeError(f'unsupported PAM rule: {stripped}')
        group, control, module, args = match.groups()
        return group.lstrip('-'), control, module, (args or '').split('#', 1)[0].strip()

    def audit_non_auth(source, chain):
        for line in source.splitlines():
            parsed = rule(line)
            if parsed is None:
                continue
            group, control, target, args = parsed
            if group == 'auth':
                raise RuntimeError(f'authentication hidden in non-auth include: {chain[-1]}')
            if group == '@include':
                audit_non_auth(included(target, chain), (*chain, target))

    def auth(source, chain, retained_only=False):
        nonlocal inserted, credentials
        output = []
        for line in source.splitlines(keepends=True):
            parsed = rule(line)
            if parsed is None:
                continue
            group, control, target, args = parsed
            if group == '@include' or (group == 'auth' and control in ('include', 'substack')):
                if target not in profile.auth_includes and target not in profile.retained_auth_includes:
                    raise RuntimeError(f'unsupported PAM auth include: {target}')
                nested = included(target, chain)
                if target in profile.retained_auth_includes:
                    auth(nested, (*chain, target), True)
                    output.append(line if line.endswith('\n') else line + '\n')
                else:
                    output.extend(auth(nested, (*chain, target), retained_only))
                continue
            if group != 'auth':
                continue
            if target in PASSWORD_MODULES:
                if retained_only:
                    raise RuntimeError(f'password authentication hidden in retained include: {target}')
                credentials += 1
                if not inserted:
                    output.append(f'auth requisite {module_path}\n')
                    inserted = True
                continue
            if target in BRANCH_MODULES and not retained_only:
                continue
            if profile.name == 'fedora' and target in ('pam_usertype.so', 'pam_localuser.so'):
                expected_args = 'isregular' if target == 'pam_usertype.so' else ''
                if retained_only or control != '[default=1 ignore=ignore success=ok]' or args != expected_args:
                    raise RuntimeError(f'unsupported password-selector control: {target}')
                # Authselect selectors route between the discarded local/SSSD
                # password providers. Retaining their jumps could bypass OTP.
                continue
            if target == 'pam_faillock.so' and target in profile.retained_auth_modules:
                if 'authfail' in args.split():
                    if retained_only:
                        raise RuntimeError('password failure branch in retained PAM include')
                    continue
            if target not in profile.retained_auth_modules:
                raise RuntimeError(f'unsupported PAM authentication module: {target}')
            if control not in ('required', 'requisite', 'optional'):
                # Never retain sufficient/done/jump controls that could bypass OTP.
                raise RuntimeError(f'unsupported control on retained PAM module: {target} {control}')
            output.append(line if line.endswith('\n') else line + '\n')
        return output

    output = []
    for line in text.splitlines(keepends=True):
        parsed = rule(line)
        if parsed is None:
            output.append(line)
            continue
        group, control, target, args = parsed
        if group == '@include':
            source = included(target, ())
            if target in profile.auth_includes or target in profile.retained_auth_includes:
                # Removing a whole @include must not remove account/session rules.
                if any(item and item[0] not in ('auth', '@include') for item in map(rule, source.splitlines())):
                    raise RuntimeError(f'mixed management groups in auth include: {target}')
                output.extend(auth(source, (target,), target in profile.retained_auth_includes))
            else:
                audit_non_auth(source, (target,))
                output.append(line)
        elif group == 'auth':
            if control in ('include', 'substack'):
                output.extend(auth(line, ()))
            else:
                # Root auth modules are policy gates, not arbitrary password stacks.
                if target not in profile.retained_auth_modules:
                    raise RuntimeError(f'unsupported direct PAM authentication module: {target}')
                output.extend(auth(line, (), True))
        else:
            output.append(line)
    if not inserted or not credentials:
        raise RuntimeError('no recognized password authentication stack found')
    return ''.join(output)
