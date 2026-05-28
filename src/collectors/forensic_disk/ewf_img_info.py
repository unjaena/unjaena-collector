# -*- coding: utf-8 -*-
"""
ewf_img_info — Legacy pytsk3 bridge module (DEPRECATED)

All pytsk3-based classes and functions have been removed.
ForensicDiskAccessor now uses dissect for all filesystem access.

Only detect_os_from_filesystem() remains as it is a pure utility
function used by device_enumerators.py and __init__.py.

Removed (2026-03-22):
- EwfImgInfo(pytsk3.Img_Info)        — replaced by CachedBackendIO + dissect
- BackendImgInfo(pytsk3.Img_Info)    — replaced by CachedBackendIO + dissect
- RawImgInfo(pytsk3.Img_Info)        — replaced by CachedBackendIO + dissect
- open_e01_as_pytsk3()               — use ForensicDiskAccessor.from_e01()
- open_raw_as_pytsk3()               — use ForensicDiskAccessor.from_raw()
- detect_filesystem_type()           — use ForensicDiskAccessor.list_partitions()
- detect_partitions_pytsk3()         — use ForensicDiskAccessor.list_partitions()
"""

import logging

logger = logging.getLogger(__name__)

# Legacy flags — kept for backward compatibility with __init__.py imports
PYEWF_AVAILABLE = False
try:
    import pyewf
    PYEWF_AVAILABLE = True
except ImportError:
    pass

PYTSK3_AVAILABLE = False  # pytsk3 is no longer used


def detect_os_from_filesystem(filesystem_type: str) -> str:
    """
    Infer OS from filesystem type

    Args:
        filesystem_type: Filesystem type ('NTFS', 'ext4', 'HFS+', etc.)

    Returns:
        OS type ('windows', 'linux', 'macos', 'unknown')
    """
    fs_lower = filesystem_type.lower()

    if fs_lower in ('ntfs', 'fat32', 'fat16', 'fat12', 'exfat'):
        return 'windows'
    elif fs_lower in ('ext2', 'ext3', 'ext4'):
        return 'linux'
    elif fs_lower in ('apfs', 'hfs+', 'hfs', 'hfsx'):
        return 'macos'
    else:
        return 'unknown'


# ------------------------------------------------------------------
# Removed symbols — raise clear errors if anyone still tries to use them
# ------------------------------------------------------------------

def open_e01_as_pytsk3(*args, **kwargs):
    """REMOVED: Use ForensicDiskAccessor.from_e01() instead."""
    raise NotImplementedError(
        "open_e01_as_pytsk3() has been removed. "
        "Use ForensicDiskAccessor.from_e01() instead."
    )


def open_raw_as_pytsk3(*args, **kwargs):
    """REMOVED: Use ForensicDiskAccessor.from_raw() instead."""
    raise NotImplementedError(
        "open_raw_as_pytsk3() has been removed. "
        "Use ForensicDiskAccessor.from_raw() instead."
    )


def detect_filesystem_type(*args, **kwargs):
    """REMOVED: Use ForensicDiskAccessor.list_partitions() instead."""
    raise NotImplementedError(
        "detect_filesystem_type() has been removed. "
        "Use ForensicDiskAccessor.list_partitions() instead."
    )


def detect_partitions_pytsk3(*args, **kwargs):
    """REMOVED: Use ForensicDiskAccessor.list_partitions() instead."""
    raise NotImplementedError(
        "detect_partitions_pytsk3() has been removed. "
        "Use ForensicDiskAccessor.list_partitions() instead."
    )


# Removed classes — provide stubs that raise on instantiation
class EwfImgInfo:
    """REMOVED: Use ForensicDiskAccessor.from_e01() instead."""
    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "EwfImgInfo has been removed. "
            "Use ForensicDiskAccessor.from_e01() with CachedBackendIO + dissect."
        )


class BackendImgInfo:
    """REMOVED: Use CachedBackendIO + dissect instead."""
    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "BackendImgInfo has been removed. "
            "Use CachedBackendIO in forensic_disk_accessor.py instead."
        )


class RawImgInfo:
    """REMOVED: Use ForensicDiskAccessor.from_raw() instead."""
    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "RawImgInfo has been removed. "
            "Use ForensicDiskAccessor.from_raw() with CachedBackendIO + dissect."
        )
