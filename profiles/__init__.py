"""Select a supported PAM/service profile without guessing unknown distributions."""
import platform


def select_profile(name=None, os_release=None):
    from .alpine import PROFILE as alpine
    from .arch import PROFILE as arch
    from .debian import PROFILE as debian
    from .fedora import PROFILE as fedora
    profiles = (debian, fedora, arch, alpine)
    if name:
        for profile in profiles:
            if profile.name == name:
                return profile
        raise RuntimeError(f'unknown profile: {name}')
    release = os_release if os_release is not None else platform.freedesktop_os_release()
    identifier = release.get('ID', '')
    for profile in profiles:
        if identifier in profile.os_ids:
            return profile
    # Derivative compatibility must be opted into by the profile, not inferred
    # just because a distro lists a familiar ancestor in ID_LIKE.
    ancestors = release.get('ID_LIKE', '').split()
    for profile in profiles:
        if any(ancestor in profile.id_like for ancestor in ancestors):
            return profile
    raise RuntimeError(f'unsupported distribution {identifier!r}; choose an audited --profile explicitly')
