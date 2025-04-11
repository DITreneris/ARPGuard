"""
Version management for ARP Guard.
"""
__version__ = "1.0.0"
__version_info__ = (1, 0, 0)
__release_date__ = "2025-04-11"

def get_version():
    """Return the current version of ARP Guard."""
    return __version__

def get_version_info():
    """Return the version info tuple."""
    return __version_info__

def get_release_date():
    """Return the release date of the current version."""
    return __release_date__

def is_compatible(version):
    """Check if the given version is compatible with the current version."""
    try:
        major, minor, patch = map(int, version.split('.'))
        current_major, current_minor, _ = __version_info__
        return major == current_major and minor <= current_minor
    except (ValueError, AttributeError):
        return False 