"""
ForensicDiskAccessor - Raw disk access for locked files

Provides direct sector-level access to NTFS volumes,
bypassing Windows filesystem locks.

Supports:
- NTFS/FAT via custom MFT/FAT parsers
- ext4/HFS+/APFS via pytsk3 (EwfImgInfo wrapper)
"""

try:
    from .forensic_disk_accessor import ForensicDiskAccessor
    from .unified_disk_reader import DiskError, BitLockerError
    from .disk_backends import (
        PhysicalDiskBackend,
        E01DiskBackend,
        RAWImageBackend
    )
    from .file_content_extractor import FileContentExtractor
    FORENSIC_DISK_AVAILABLE = True
except ImportError as e:
    FORENSIC_DISK_AVAILABLE = False
    ForensicDiskAccessor = None
    DiskError = None
    BitLockerError = None
    _import_error = str(e)

# [NEW] EwfImgInfo - pyewf to pytsk3 bridge (ext4/HFS+/APFS support)
try:
    from .ewf_img_info import (
        EwfImgInfo,
        RawImgInfo,
        open_e01_as_pytsk3,
        open_raw_as_pytsk3,
        detect_filesystem_type,
        detect_partitions_pytsk3,
        detect_os_from_filesystem,
        PYEWF_AVAILABLE,
        PYTSK3_AVAILABLE
    )
    EWF_IMG_INFO_AVAILABLE = PYEWF_AVAILABLE and PYTSK3_AVAILABLE
except ImportError:
    EwfImgInfo = None
    RawImgInfo = None
    open_e01_as_pytsk3 = None
    open_raw_as_pytsk3 = None
    detect_filesystem_type = None
    detect_partitions_pytsk3 = None
    detect_os_from_filesystem = None
    PYEWF_AVAILABLE = False
    PYTSK3_AVAILABLE = False
    EWF_IMG_INFO_AVAILABLE = False

__all__ = [
    'ForensicDiskAccessor',
    'DiskError',
    'BitLockerError',
    'PhysicalDiskBackend',
    'E01DiskBackend',
    'RAWImageBackend',
    'FileContentExtractor',
    'FORENSIC_DISK_AVAILABLE',
    # EwfImgInfo (pytsk3 bridge)
    'EwfImgInfo',
    'RawImgInfo',
    'open_e01_as_pytsk3',
    'open_raw_as_pytsk3',
    'detect_filesystem_type',
    'detect_partitions_pytsk3',
    'detect_os_from_filesystem',
    'PYEWF_AVAILABLE',
    'PYTSK3_AVAILABLE',
    'EWF_IMG_INFO_AVAILABLE',
]
