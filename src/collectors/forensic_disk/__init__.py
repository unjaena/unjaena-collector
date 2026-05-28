"""
ForensicDiskAccessor - Raw disk access for locked files

Provides direct sector-level access to NTFS volumes,
bypassing Windows filesystem locks.

Supports:
- NTFS/FAT via custom MFT/FAT parsers
- ext4/HFS+/APFS/XFS/Btrfs/UFS via dissect
"""

try:
    from .forensic_disk_accessor import ForensicDiskAccessor
    from .unified_disk_reader import DiskError, BitLockerError
    from .disk_backends import (
        PhysicalDiskBackend,
        E01DiskBackend,
        RAWImageBackend,
        VMDKDiskBackend,
        VHDDiskBackend,
        VHDXDiskBackend,
        QCOW2DiskBackend,
        VDIDiskBackend,
        DMGDiskBackend,
        create_disk_backend,
    )
    from .file_content_extractor import FileContentExtractor
    FORENSIC_DISK_AVAILABLE = True
except ImportError as e:
    FORENSIC_DISK_AVAILABLE = False
    ForensicDiskAccessor = None
    DiskError = None
    BitLockerError = None
    _import_error = str(e)

# ewf_img_info — only detect_os_from_filesystem() is still a live utility.
# The pytsk3 bridge classes/functions are removed stubs that raise NotImplementedError.
try:
    from .ewf_img_info import (
        detect_os_from_filesystem,
        PYEWF_AVAILABLE,
    )
except ImportError:
    detect_os_from_filesystem = None
    PYEWF_AVAILABLE = False

# pytsk3 is no longer used anywhere in this package
PYTSK3_AVAILABLE = False
EWF_IMG_INFO_AVAILABLE = False

__all__ = [
    'ForensicDiskAccessor',
    'DiskError',
    'BitLockerError',
    'PhysicalDiskBackend',
    'E01DiskBackend',
    'RAWImageBackend',
    'VMDKDiskBackend',
    'VHDDiskBackend',
    'VHDXDiskBackend',
    'QCOW2DiskBackend',
    'VDIDiskBackend',
    'DMGDiskBackend',
    'create_disk_backend',
    'FileContentExtractor',
    'FORENSIC_DISK_AVAILABLE',
    # Legacy utility (no pytsk3 dependency)
    'detect_os_from_filesystem',
    'PYEWF_AVAILABLE',
    'PYTSK3_AVAILABLE',
    'EWF_IMG_INFO_AVAILABLE',
]
