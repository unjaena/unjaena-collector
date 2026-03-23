# -*- coding: utf-8 -*-
"""
Forensic Disk Accessor - Unified Forensic Disk Access API

Accesses local physical disks and E01/RAW images through a unified interface.
Completely bypasses Windows filesystem to read locked files.

Features:
- Physical disk (\\\\.\\PhysicalDrive{N}) access
- E01/EWF forensic image access
- RAW/DD image file access
- Automatic partition detection (MBR/GPT)
- Automatic filesystem detection (NTFS, FAT32, exFAT, ext2/3/4, XFS, Btrfs, UFS)
- MFT/FAT based file reading (NTFS native)
- dissect-based file extraction for non-NTFS filesystems
- Deleted file recovery (NTFS via MFT flags, others via dissect inode scanning)
- ADS (Alternate Data Streams) support (NTFS only)

Usage:
    from core.engine.collectors.filesystem.forensic_disk_accessor import ForensicDiskAccessor

    # Physical disk access
    with ForensicDiskAccessor.from_physical_disk(0) as disk:
        disk.select_partition(0)  # C:
        data = disk.read_file("/Windows/System32/config/SYSTEM")

    # E01 image access
    with ForensicDiskAccessor.from_e01("evidence.E01") as disk:
        disk.select_partition(0)
        for chunk in disk.stream_file("/pagefile.sys"):
            analyze(chunk)

    # Non-NTFS filesystem (ext4, FAT32, XFS, Btrfs, UFS, etc.)
    with ForensicDiskAccessor.from_e01("linux.E01") as disk:
        disk.select_partition(0)  # ext4 partition
        catalog = disk.scan_all_files(include_deleted=True)
        data = disk.read_file("/etc/passwd")

    # Full scan including deleted files
    catalog = disk.scan_all_files(include_deleted=True)
"""

import io
import stat
import struct
import logging
from typing import Optional, List, Dict, Generator, Any, Union, Tuple
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone

from .unified_disk_reader import (
    UnifiedDiskReader,
    DiskInfo,
    PartitionInfo,
    DiskSourceType,
    DiskError,
    DiskNotFoundError,
    PartitionError,
    FilesystemError
)
from .disk_backends import (
    PhysicalDiskBackend,
    E01DiskBackend,
    RAWImageBackend,
    create_disk_backend
)
from .file_content_extractor import FileContentExtractor, FileMetadata, DataRun

logger = logging.getLogger(__name__)

# ==============================================================================
# dissect filesystem support (replaces pytsk3 for non-NTFS)
# ==============================================================================

# Map filesystem type strings to (module_path, class_name)
_DISSECT_FS_MAP = {
    'ext2':  ('dissect.extfs', 'ExtFS'),
    'ext3':  ('dissect.extfs', 'ExtFS'),
    'ext4':  ('dissect.extfs', 'ExtFS'),
    'FAT12': ('dissect.fat',   'FATFS'),
    'FAT16': ('dissect.fat',   'FATFS'),
    'FAT32': ('dissect.fat',   'FATFS'),
    'exFAT': ('dissect.fat.exfat', 'ExFAT'),
    'XFS':   ('dissect.xfs',   'XFS'),
    'Btrfs': ('dissect.btrfs', 'Btrfs'),
    'UFS':   ('dissect.ffs',   'FFS'),
    'APFS':  ('dissect.apfs',  'APFS'),
}

# HFS+ uses pyfshfs (libfshfs) — separate from dissect
_HFS_FILESYSTEMS = frozenset({'HFS', 'HFS+', 'HFSX'})

# Check pyfshfs availability
try:
    import pyfshfs
    PYFSHFS_AVAILABLE = True
except ImportError:
    PYFSHFS_AVAILABLE = False

# Filesystems that use native MFT-based extraction
_NTFS_FILESYSTEMS = frozenset({'NTFS'})

# Filesystems supported by dissect fallback
_DISSECT_SUPPORTED_FILESYSTEMS = frozenset(_DISSECT_FS_MAP.keys())

# All non-NTFS supported filesystems
_ALL_SUPPORTED_FILESYSTEMS = _DISSECT_SUPPORTED_FILESYSTEMS | _HFS_FILESYSTEMS


def _import_dissect_fs(fs_type: str):
    """
    Dynamically import and return the dissect filesystem class for the given type.

    Returns:
        The filesystem class, or None if unavailable.
    """
    entry = _DISSECT_FS_MAP.get(fs_type)
    if entry is None:
        return None

    module_path, class_name = entry
    try:
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except (ImportError, AttributeError) as e:
        logger.warning(f"dissect module for {fs_type} not available: {e}")
        return None


# ==============================================================================
# CachedBackendIO - BinaryIO wrapper around UnifiedDiskReader with caching
# ==============================================================================

class CachedBackendIO(io.RawIOBase):
    """
    Wraps a UnifiedDiskReader as a BinaryIO (seekable, readable) for dissect
    filesystem constructors.  Provides partition offset/size handling and a
    1MB-block LRU cache (ported from BackendImgInfo in ewf_img_info.py) to
    minimize random I/O through virtual-disk translation layers.

    All dissect filesystem classes accept a BinaryIO (file-like object with
    seek/read/tell) in their constructor.
    """

    _CACHE_BLOCK_SIZE = 1024 * 1024   # 1 MB per cache block
    _CACHE_MAX_BLOCKS = 256           # 256 MB max cache

    def __init__(self, backend: UnifiedDiskReader, offset: int = 0, size: int = 0):
        """
        Args:
            backend: UnifiedDiskReader (PhysicalDisk, E01, RAW, VDI, etc.)
            offset:  Partition start offset in bytes.
            size:    Partition size in bytes (0 = to end of disk).
        """
        super().__init__()
        self._backend = backend
        self._offset = offset
        self._size = size if size else (backend.get_size() - offset)
        self._pos = 0            # Current position relative to partition start
        self._cache: Dict[int, bytes] = {}
        self._cache_order: List[int] = []   # LRU order (oldest first)

    # -- BinaryIO interface --------------------------------------------------

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:          # SEEK_SET
            self._pos = offset
        elif whence == 1:        # SEEK_CUR
            self._pos += offset
        elif whence == 2:        # SEEK_END
            self._pos = self._size + offset
        else:
            raise ValueError(f"Invalid whence: {whence}")
        self._pos = max(0, min(self._pos, self._size))
        return self._pos

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = self._size - self._pos
        if size <= 0 or self._pos >= self._size:
            return b''

        # Clamp to partition boundary
        size = min(size, self._size - self._pos)

        # Absolute offset in the disk image
        abs_offset = self._offset + self._pos

        # For very large reads (>4 MB), bypass cache to avoid thrashing
        if size > 4 * self._CACHE_BLOCK_SIZE:
            data = self._backend.read(abs_offset, size)
            self._pos += len(data)
            return data

        result = bytearray()
        remaining = size

        while remaining > 0:
            block_idx = (self._offset + self._pos) // self._CACHE_BLOCK_SIZE
            block_offset = (self._offset + self._pos) % self._CACHE_BLOCK_SIZE
            block_data = self._read_cached_block(block_idx)

            if not block_data:
                break

            available = len(block_data) - block_offset
            chunk_size = min(remaining, available)
            result.extend(block_data[block_offset:block_offset + chunk_size])
            self._pos += chunk_size
            remaining -= chunk_size

        return bytes(result)

    def readinto(self, b) -> int:
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def _read_cached_block(self, block_idx: int) -> bytes:
        """Read a 1 MB block, using cache if available (LRU eviction)."""
        if block_idx in self._cache:
            try:
                self._cache_order.remove(block_idx)
            except ValueError:
                pass
            self._cache_order.append(block_idx)
            return self._cache[block_idx]

        offset = block_idx * self._CACHE_BLOCK_SIZE
        disk_size = self._backend.get_size()
        read_size = min(self._CACHE_BLOCK_SIZE, disk_size - offset)
        if read_size <= 0:
            return b''

        data = self._backend.read(offset, read_size)

        while len(self._cache) >= self._CACHE_MAX_BLOCKS:
            oldest = self._cache_order.pop(0)
            self._cache.pop(oldest, None)

        self._cache[block_idx] = data
        self._cache_order.append(block_idx)
        return data

    def close(self):
        """Release cache memory.  Backend lifecycle managed by caller."""
        self._cache.clear()
        self._cache_order.clear()
        super().close()


# ==============================================================================
# dissect node helper functions (cross-filesystem abstraction)
# ==============================================================================

def _node_filename(node, fs_type: str) -> str:
    """
    Extract filename from a dissect filesystem node.

    Different dissect implementations store the name in different attributes:
    - ExtFS/XFS: node.filename  (str or None)
    - FATFS: node.name  (str)
    - Btrfs: node.path (property) or obtained from iterdir tuple
    - FFS: node.name (str or None)
    - ExFAT: obtained from dict key during iteration
    - HFS+/HFSX: node.name (str) via pyfshfs
    """
    try:
        # HFS+/HFSX (pyfshfs): node.name is a str
        if fs_type in _HFS_FILESYSTEMS:
            if hasattr(node, 'name') and node.name is not None:
                return str(node.name)
            return ""

        # ExtFS, XFS
        if hasattr(node, 'filename') and node.filename is not None:
            return str(node.filename)

        # FAT, FFS
        if hasattr(node, 'name') and node.name is not None:
            name = str(node.name)
            # FAT directories have trailing /
            return name.rstrip('/')

        # Btrfs
        if hasattr(node, 'path'):
            try:
                p = node.path
                if '/' in p:
                    return p.rsplit('/', 1)[-1]
                return p
            except Exception:
                pass

        return ""
    except Exception:
        return ""


def _node_is_dir(node, fs_type: str) -> bool:
    """Check whether a dissect node represents a directory."""
    try:
        # HFS+/HFSX (pyfshfs): check file_mode with S_ISDIR
        if fs_type in _HFS_FILESYSTEMS:
            if hasattr(node, 'file_mode') and node.file_mode is not None:
                return stat.S_ISDIR(node.file_mode)
            # Fallback: directories have sub_file_entries
            if hasattr(node, 'number_of_sub_file_entries'):
                return node.number_of_sub_file_entries > 0
            return False

        # Btrfs / FFS have explicit is_dir()
        if hasattr(node, 'is_dir'):
            return node.is_dir()

        # FAT has is_directory() as a method
        if hasattr(node, 'is_directory') and callable(node.is_directory):
            return node.is_directory()

        # ExtFS / XFS use stat-based filetype property
        if hasattr(node, 'filetype'):
            return node.filetype == stat.S_IFDIR

        return False
    except Exception:
        return False


def _node_inum(node, fs_type: str) -> int:
    """
    Extract inode number from a dissect node.

    - ExtFS/XFS/FFS/Btrfs: node.inum
    - FAT: node.cluster (FAT has no inodes; use start cluster as pseudo-inode)
    - ExFAT: node.cluster if available
    - HFS+/HFSX: node.identifier (CNID, Catalog Node ID)
    """
    try:
        # HFS+/HFSX (pyfshfs): use CNID (identifier)
        if fs_type in _HFS_FILESYSTEMS:
            if hasattr(node, 'identifier'):
                return int(node.identifier)
            return 0

        if hasattr(node, 'inum'):
            return int(node.inum)

        # FAT uses start cluster as identifier
        if hasattr(node, 'cluster'):
            return int(node.cluster)

        return 0
    except Exception:
        return 0


def _node_size(node) -> int:
    """Extract file size from a dissect node."""
    try:
        if hasattr(node, 'size'):
            s = node.size
            if callable(s):
                return int(s())
            return int(s)
        return 0
    except Exception:
        return 0


def _node_is_deleted(node, fs_type: str) -> bool:
    """
    Check whether a dissect node represents a deleted file.

    - ExtFS: dtime > epoch(0) indicates deletion
    - XFS: inode nlink == 0 or similar
    - FAT: handled at directory entry level (first byte 0xE5) -- dissect
      skips deleted entries during iteration, so anything yielded is live.
    - Btrfs: deleted items are not reachable via tree traversal
    - FFS: use inode link count
    """
    try:
        fs_lower = fs_type.lower()

        # ext2/3/4: dtime != epoch(0) means deleted
        if fs_lower.startswith('ext'):
            if hasattr(node, 'dtime'):
                dtime = node.dtime
                if isinstance(dtime, datetime):
                    # dtime > 1970-01-01 means the file was deleted
                    return dtime.timestamp() > 0
            # Also check i_links_count via raw inode
            if hasattr(node, 'inode') and hasattr(node.inode, 'i_links_count'):
                return node.inode.i_links_count == 0
            return False

        # FFS: use mode / link count
        if fs_lower == 'ufs':
            if hasattr(node, 'inode') and hasattr(node.inode, 'di_nlink'):
                return node.inode.di_nlink == 0
            return False

        # HFS+/HFSX: pyfshfs does not expose deleted entries
        # FAT/exFAT/XFS/Btrfs: dissect only yields live entries
        return False
    except Exception:
        return False


def _node_timestamps(node, fs_type: str) -> Tuple[int, int, int, int]:
    """
    Extract timestamps from a dissect node.

    Returns:
        (created, modified, accessed, changed) as POSIX int seconds.
        Returns 0 for unavailable timestamps.
    """
    def _dt_to_int(dt_val) -> int:
        """Convert datetime or timestamp to int."""
        if dt_val is None:
            return 0
        try:
            if isinstance(dt_val, (int, float)):
                return int(dt_val)
            if isinstance(dt_val, datetime):
                return int(dt_val.timestamp())
            return 0
        except (OSError, OverflowError, ValueError):
            return 0

    created = 0
    modified = 0
    accessed = 0
    changed = 0

    try:
        # HFS+/HFSX (pyfshfs): uses creation_time, modification_time, access_time
        if fs_type in _HFS_FILESYSTEMS:
            if hasattr(node, 'creation_time'):
                created = _dt_to_int(node.creation_time)
            if hasattr(node, 'modification_time'):
                modified = _dt_to_int(node.modification_time)
            if hasattr(node, 'access_time'):
                accessed = _dt_to_int(node.access_time)
            # HFS+ has no separate metadata-change time
            return (created, modified, accessed, 0)

        # Created time (crtime / btime / ctime for FAT)
        if hasattr(node, 'crtime'):
            created = _dt_to_int(node.crtime)
        elif hasattr(node, 'btime'):
            created = _dt_to_int(node.btime)
        elif hasattr(node, 'otime'):  # Btrfs
            created = _dt_to_int(node.otime)
        elif hasattr(node, 'ctime') and fs_type in ('FAT12', 'FAT16', 'FAT32', 'exFAT'):
            # FAT ctime = creation time (not change time like POSIX)
            created = _dt_to_int(node.ctime)

        # Modified time
        if hasattr(node, 'mtime'):
            modified = _dt_to_int(node.mtime)

        # Accessed time
        if hasattr(node, 'atime'):
            accessed = _dt_to_int(node.atime)

        # Changed time (metadata change, POSIX ctime -- not FAT)
        if fs_type not in ('FAT12', 'FAT16', 'FAT32', 'exFAT'):
            if hasattr(node, 'ctime'):
                changed = _dt_to_int(node.ctime)

    except Exception as e:
        logger.debug(f"Timestamp extraction failed for {fs_type}: {e}")

    return (created, modified, accessed, changed)


# ==============================================================================
# Partition Table Parsing
# ==============================================================================

class PartitionTableType:
    """Partition table type"""
    MBR = "mbr"
    GPT = "gpt"
    UNKNOWN = "unknown"


# GPT partition type GUIDs (major types only)
GPT_TYPE_GUIDS = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Basic Data (NTFS/FAT)",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "LDM Metadata",
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "LDM Data",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux Filesystem",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux home",
}

# MBR partition types
MBR_PARTITION_TYPES = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 <32MB",
    0x05: "Extended",
    0x06: "FAT16",
    0x07: "NTFS/HPFS",
    0x0B: "FAT32 CHS",
    0x0C: "FAT32 LBA",
    0x0E: "FAT16 LBA",
    0x0F: "Extended LBA",
    0x11: "Hidden FAT12",
    0x14: "Hidden FAT16 <32MB",
    0x16: "Hidden FAT16",
    0x17: "Hidden NTFS",
    0x1B: "Hidden FAT32",
    0x1C: "Hidden FAT32 LBA",
    0x1E: "Hidden FAT16 LBA",
    0x27: "Windows RE",
    0x82: "Linux swap",
    0x83: "Linux",
    0x85: "Linux Extended",
    0x8E: "Linux LVM",
    0xEE: "GPT Protective",
    0xEF: "EFI System",
    0xFD: "Linux RAID",
}


@dataclass
class FileCatalogEntry:
    """File catalog entry"""
    inode: int
    filename: str
    full_path: str = ""
    size: int = 0
    is_directory: bool = False
    is_deleted: bool = False
    parent_inode: int = 0
    created_time: int = 0
    modified_time: int = 0
    has_data_runs: bool = False
    ads_streams: List[str] = None

    def __post_init__(self):
        if self.ads_streams is None:
            self.ads_streams = []

    @property
    def name(self) -> str:
        """Alias for filename (compatibility)"""
        return self.filename


# ==============================================================================
# Forensic Disk Accessor
# ==============================================================================

class ForensicDiskAccessor:
    """
    Unified Forensic Disk Access API

    Accesses local disks and E01 images through a unified interface.
    Reads files on raw sector basis, bypassing Windows filesystem.

    Usage:
        # Factory methods
        disk = ForensicDiskAccessor.from_physical_disk(0)
        disk = ForensicDiskAccessor.from_e01("evidence.E01")
        disk = ForensicDiskAccessor.from_raw("disk.dd")

        # Partition selection
        partitions = disk.list_partitions()
        disk.select_partition(0)

        # File operations
        data = disk.read_file("/Windows/System32/config/SYSTEM")
        zone_id = disk.read_file_by_inode(12345, stream_name="Zone.Identifier")

        # Scan all files
        catalog = disk.scan_all_files(include_deleted=True)
    """

    def __init__(self, backend: UnifiedDiskReader):
        """
        Args:
            backend: UnifiedDiskReader implementation
        """
        self._backend = backend
        self._partitions: List[PartitionInfo] = []
        self._partition_table_type: str = PartitionTableType.UNKNOWN
        self._selected_partition: Optional[int] = None
        self._extractor: Optional[FileContentExtractor] = None

        # dissect filesystem handle (for non-NTFS filesystems)
        self._dissect_fs: Optional[Any] = None      # dissect filesystem instance
        self._dissect_fh: Optional[Any] = None       # CachedBackendIO
        self._dissect_fs_type: Optional[str] = None  # Filesystem type string

        # MFT index cache (path -> inode)
        self._path_cache: Dict[str, int] = {}

        # MFT parent-child index cache (parent_inode -> [child_inodes])
        self._parent_child_index: Dict[int, List[int]] = {}
        self._parent_index_built: bool = False

        # Filename map cache ((parent_inode, lowercase_name) -> inode)
        self._name_to_inode_map: Dict[tuple, int] = {}

        # Partition detection
        self._detect_partitions()

    # ==========================================================================
    # Factory Methods
    # ==========================================================================

    @classmethod
    def from_physical_disk(cls, drive_number: int) -> 'ForensicDiskAccessor':
        """
        Create accessor from physical disk

        Args:
            drive_number: Drive number (0, 1, 2, ...)

        Returns:
            ForensicDiskAccessor instance

        Raises:
            DiskNotFoundError: Drive not found
            DiskPermissionError: Administrator privileges required
        """
        backend = PhysicalDiskBackend(drive_number)
        return cls(backend)

    @classmethod
    def from_e01(cls, e01_path: str) -> 'ForensicDiskAccessor':
        """
        Create accessor from E01 image

        Args:
            e01_path: E01 file path (.E01, .E02, ... auto-detected)

        Returns:
            ForensicDiskAccessor instance

        Raises:
            DiskNotFoundError: File not found
        """
        backend = E01DiskBackend(e01_path)
        return cls(backend)

    @classmethod
    def from_raw(cls, raw_path: str) -> 'ForensicDiskAccessor':
        """
        Create accessor from RAW/DD image

        Args:
            raw_path: RAW image file path

        Returns:
            ForensicDiskAccessor instance
        """
        backend = RAWImageBackend(raw_path)
        return cls(backend)

    @classmethod
    def auto_detect(cls, source: str) -> 'ForensicDiskAccessor':
        """
        Create accessor by auto-detecting source type

        Args:
            source: Disk number (numeric) or image file path

        Returns:
            ForensicDiskAccessor instance
        """
        backend = create_disk_backend(source)
        return cls(backend)

    # ==========================================================================
    # Partition Management
    # ==========================================================================

    def _detect_partitions(self):
        """Detect partition table (MBR/GPT/Volume Image)"""
        # [2026-01] Volume image support: check filesystem signature first
        # Both MBR and VBR have 0x55AA at bytes 510-511,
        # so we need to check NTFS/FAT filesystem signatures first
        first_sector = self._backend.read(0, 512)

        # Check NTFS VBR signature (bytes 3-10: "NTFS    ")
        if first_sector[3:11] == b'NTFS    ':
            self._create_volume_image_partition('NTFS')
            return

        # Check BitLocker signature (bytes 3-10: "-FVE-FS-")
        if first_sector[3:11] == b'-FVE-FS-':
            self._create_volume_image_partition('BitLocker')
            return

        # Check exFAT signature (bytes 3-10: "EXFAT   ")
        if first_sector[3:11] == b'EXFAT   ':
            self._create_volume_image_partition('exFAT')
            return

        # Check FAT32 signature (bytes 82-89: "FAT32   ")
        if first_sector[82:90] == b'FAT32   ':
            self._create_volume_image_partition('FAT32')
            return

        # Check FAT16/FAT12 signature (bytes 54-61)
        if first_sector[54:62] in (b'FAT16   ', b'FAT12   '):
            fs = 'FAT16' if first_sector[54:62] == b'FAT16   ' else 'FAT12'
            self._create_volume_image_partition(fs)
            return

        # Check MBR signature
        if first_sector[510:512] != b'\x55\xAA':
            # No MBR signature and no filesystem signature
            # Check additional filesystems (ext, APFS, HFS+, etc.)
            fs_type = self._detect_filesystem(0)
            if fs_type != "Unknown":
                self._create_volume_image_partition(fs_type)
                return
            logger.warning("Invalid MBR signature and no filesystem detected at offset 0")
            return

        # Check GPT (Protective MBR partition type 0xEE)
        if first_sector[450] == 0xEE:
            self._partition_table_type = PartitionTableType.GPT
            self._parse_gpt()
        else:
            self._partition_table_type = PartitionTableType.MBR
            self._parse_mbr(first_sector)

        logger.info(f"Detected {self._partition_table_type.upper()} with {len(self._partitions)} partition(s)")

    def _create_volume_image_partition(self, fs_type: str):
        """Create volume image as a single partition"""
        self._partition_table_type = "volume"  # Volume image
        total_size = self._backend.get_size()

        # Determine partition type code
        type_codes = {
            'NTFS': 0x07, 'BitLocker': 0x07,
            'FAT32': 0x0B, 'FAT16': 0x06, 'FAT12': 0x01,
            'exFAT': 0x07, 'ext4': 0x83, 'ext3': 0x83, 'ext2': 0x83,
            'APFS': 0xAF, 'HFS+': 0xAF,
        }
        ptype = type_codes.get(fs_type, 0x07)

        partition = PartitionInfo(
            index=0,
            partition_type=ptype,
            type_name=f"Volume Image ({fs_type})",
            offset=0,
            size=total_size,
            lba_start=0,
            sector_count=total_size // 512,
            filesystem=fs_type,
            is_bootable=False
        )
        self._partitions.append(partition)
        logger.info(f"Detected volume image: {fs_type}, size={total_size / (1024**3):.2f} GB")

    def _parse_mbr(self, mbr: bytes):
        """Parse MBR partition table"""
        sector_size = 512

        for i in range(4):
            entry_offset = 446 + (i * 16)
            entry = mbr[entry_offset:entry_offset + 16]

            # Partition type
            partition_type = entry[4]

            if partition_type == 0:
                continue

            # LBA start and sector count
            lba_start = struct.unpack('<I', entry[8:12])[0]
            sector_count = struct.unpack('<I', entry[12:16])[0]

            if lba_start == 0 or sector_count == 0:
                continue

            # Bootable flag
            bootable = entry[0] == 0x80

            # Detect filesystem
            fs_type = self._detect_filesystem(lba_start * sector_size)

            partition = PartitionInfo(
                index=i,
                partition_type=partition_type,
                type_name=MBR_PARTITION_TYPES.get(partition_type, f"Unknown (0x{partition_type:02X})"),
                offset=lba_start * sector_size,
                size=sector_count * sector_size,
                lba_start=lba_start,
                sector_count=sector_count,
                filesystem=fs_type,
                is_bootable=bootable
            )

            self._partitions.append(partition)

    def _parse_gpt(self):
        """Parse GPT partition table"""
        sector_size = 512

        # Read GPT header (LBA 1)
        gpt_header = self._backend.read(sector_size, sector_size)

        if gpt_header[:8] != b'EFI PART':
            logger.warning("Invalid GPT signature")
            return

        # Partition entry information
        partition_entry_lba = struct.unpack('<Q', gpt_header[72:80])[0]
        partition_entry_count = struct.unpack('<I', gpt_header[80:84])[0]
        partition_entry_size = struct.unpack('<I', gpt_header[84:88])[0]

        # Read partition entries
        entries_per_sector = sector_size // partition_entry_size
        entry_index = 0

        for sector_offset in range(0, (partition_entry_count + entries_per_sector - 1) // entries_per_sector):
            sector_data = self._backend.read((partition_entry_lba + sector_offset) * sector_size, sector_size)

            for i in range(entries_per_sector):
                if entry_index >= partition_entry_count:
                    break

                entry_offset = i * partition_entry_size
                entry = sector_data[entry_offset:entry_offset + partition_entry_size]

                # Type GUID (empty partition is all zeros)
                type_guid_raw = entry[0:16]
                if type_guid_raw == b'\x00' * 16:
                    entry_index += 1
                    continue

                # Convert GUID to string
                type_guid = self._bytes_to_guid(type_guid_raw)

                # LBA start/end
                lba_start = struct.unpack('<Q', entry[32:40])[0]
                lba_end = struct.unpack('<Q', entry[40:48])[0]

                # Partition name (UTF-16LE)
                name_bytes = entry[56:128]
                try:
                    name = name_bytes.decode('utf-16-le').rstrip('\x00')
                except (UnicodeDecodeError, ValueError):
                    name = ""

                # Detect filesystem
                fs_type = self._detect_filesystem(lba_start * sector_size)

                partition = PartitionInfo(
                    index=entry_index,
                    partition_type=0,
                    type_guid=type_guid,
                    type_name=GPT_TYPE_GUIDS.get(type_guid.upper(), f"Unknown ({type_guid})"),
                    offset=lba_start * sector_size,
                    size=(lba_end - lba_start + 1) * sector_size,
                    lba_start=lba_start,
                    sector_count=lba_end - lba_start + 1,
                    filesystem=fs_type,
                    name=name
                )

                self._partitions.append(partition)
                entry_index += 1

    def _bytes_to_guid(self, data: bytes) -> str:
        """Convert bytes to GUID string"""
        # GUID is stored in little-endian format
        part1 = struct.unpack('<I', data[0:4])[0]
        part2 = struct.unpack('<H', data[4:6])[0]
        part3 = struct.unpack('<H', data[6:8])[0]
        part4 = data[8:10].hex().upper()
        part5 = data[10:16].hex().upper()

        return f"{part1:08X}-{part2:04X}-{part3:04X}-{part4}-{part5}"

    def _detect_filesystem(self, partition_offset: int) -> str:
        """Detect filesystem type (supports NTFS, FAT, exFAT, ext2/3/4, APFS, HFS+)"""
        try:
            vbr = self._backend.read(partition_offset, 512)

            # NTFS
            if vbr[3:11] == b'NTFS    ':
                return 'NTFS'

            # BitLocker
            if vbr[3:11] == b'-FVE-FS-':
                return 'BitLocker'

            # exFAT
            if vbr[3:11] == b'EXFAT   ':
                return 'exFAT'

            # FAT32
            if vbr[82:90] == b'FAT32   ':
                return 'FAT32'

            # FAT16
            if vbr[54:62] == b'FAT16   ':
                return 'FAT16'

            # FAT12
            if vbr[54:62] == b'FAT12   ':
                return 'FAT12'

            # APFS Container Superblock (offset 32: 'NXSB')
            # APFS has signature at offset 32, not at partition start
            if len(vbr) >= 36 and vbr[32:36] == b'NXSB':
                return 'APFS'

            # Check alternative APFS location (in some configurations)
            apfs_check = self._backend.read(partition_offset, 64)
            if len(apfs_check) >= 36 and apfs_check[32:36] == b'NXSB':
                return 'APFS'

            # HFS+ Volume Header (offset 1024: 'H+' or 'HX')
            hfs_header = self._backend.read(partition_offset + 1024, 4)
            if len(hfs_header) >= 2:
                if hfs_header[0:2] == b'H+':
                    return 'HFS+'
                elif hfs_header[0:2] == b'HX':
                    return 'HFSX'  # HFS+ with case-sensitive
                elif hfs_header[0:2] == b'BD':
                    return 'HFS'  # Original HFS (legacy)

            # ext2/3/4 (superblock at offset 1024, magic at offset 56)
            sb = self._backend.read(partition_offset + 1024, 100)
            if len(sb) >= 58 and struct.unpack('<H', sb[56:58])[0] == 0xEF53:
                # Distinguish ext version (feature flags)
                if len(sb) >= 96:
                    compat_features = struct.unpack('<I', sb[92:96])[0] if len(sb) >= 96 else 0
                    incompat_features = struct.unpack('<I', sb[96:100])[0] if len(sb) >= 100 else 0

                    # ext4 features: extents (0x40), flex_bg (0x200)
                    if incompat_features & 0x40:  # EXTENTS feature
                        return 'ext4'
                    # ext3 features: journal (0x04)
                    elif incompat_features & 0x04:  # JOURNAL feature
                        return 'ext3'
                    else:
                        return 'ext2'
                return 'ext4'  # Default

        except Exception as e:
            logger.debug(f"Filesystem detection failed: {e}")

        return "Unknown"

    def list_partitions(self) -> List[PartitionInfo]:
        """
        Return partition list

        Returns:
            List of PartitionInfo
        """
        return self._partitions.copy()

    def select_partition(self, index: int) -> None:
        """
        Select partition

        Args:
            index: Partition index (order from list_partitions)

        Raises:
            PartitionError: Invalid index
            FilesystemError: BitLocker encrypted partition
        """
        if index < 0 or index >= len(self._partitions):
            raise PartitionError(f"Invalid partition index: {index}")

        partition = self._partitions[index]
        self._selected_partition = index

        # BitLocker encrypted partition warning
        if partition.filesystem == 'BitLocker':
            from .unified_disk_reader import BitLockerError
            raise BitLockerError(
                f"Partition {index} is BitLocker encrypted. "
                f"Raw disk access cannot read encrypted data. "
                f"Use BitLocker unlock key or mount the volume first."
            )

        # Reset dissect state from previous partition selection
        if self._dissect_fs is not None:
            try:
                if hasattr(self._dissect_fs, 'close'):
                    self._dissect_fs.close()
            except Exception:
                pass
        self._dissect_fs = None
        if self._dissect_fh is not None:
            try:
                self._dissect_fh.close()
            except Exception:
                pass
        self._dissect_fh = None
        self._dissect_fs_type = None

        # Create filesystem accessor based on type
        if partition.filesystem in _NTFS_FILESYSTEMS:
            # NTFS: use native MFT-based FileContentExtractor (full feature set)
            self._extractor = FileContentExtractor(
                disk=self._backend,
                partition_offset=partition.offset,
                fs_type=partition.filesystem
            )
            logger.info(f"Selected partition {index}: {partition.filesystem} at offset {partition.offset} (NTFS native)")

        elif partition.filesystem in _DISSECT_SUPPORTED_FILESYSTEMS:
            # Non-NTFS: try dissect-based extraction
            fs_class = _import_dissect_fs(partition.filesystem)
            if fs_class is None:
                # dissect module not available -- create basic FileContentExtractor
                self._extractor = FileContentExtractor(
                    disk=self._backend,
                    partition_offset=partition.offset,
                    fs_type=partition.filesystem
                )
                logger.warning(
                    f"Selected partition {index}: {partition.filesystem} at offset {partition.offset} "
                    f"(dissect module not available - file extraction limited)"
                )
            else:
                # Create dissect filesystem handle
                try:
                    self._dissect_fh = CachedBackendIO(
                        self._backend,
                        offset=partition.offset,
                        size=partition.size
                    )
                    self._dissect_fs = fs_class(self._dissect_fh)
                    self._dissect_fs_type = partition.filesystem
                    # No FileContentExtractor needed -- dissect handles everything
                    self._extractor = None
                    logger.info(
                        f"Selected partition {index}: {partition.filesystem} at offset {partition.offset} "
                        f"(dissect extraction enabled)"
                    )
                except Exception as e:
                    logger.error(f"dissect failed to open filesystem at partition {index}: {e}")
                    # Fallback to basic FileContentExtractor
                    if self._dissect_fh is not None:
                        try:
                            self._dissect_fh.close()
                        except Exception:
                            pass
                    self._dissect_fs = None
                    self._dissect_fh = None
                    self._dissect_fs_type = None
                    self._extractor = FileContentExtractor(
                        disk=self._backend,
                        partition_offset=partition.offset,
                        fs_type=partition.filesystem
                    )
                    logger.warning(f"Falling back to basic extractor for {partition.filesystem}")
        elif partition.filesystem in _HFS_FILESYSTEMS:
            # HFS+/HFSX: use pyfshfs (libfshfs)
            if not PYFSHFS_AVAILABLE:
                self._extractor = None
                logger.warning(
                    f"HFS+ partition found but pyfshfs not installed. "
                    f"Run: pip install libfshfs-python"
                )
            else:
                try:
                    self._dissect_fh = CachedBackendIO(
                        self._backend,
                        offset=partition.offset,
                        size=partition.size
                    )
                    vol = pyfshfs.volume()
                    vol.open_file_object(self._dissect_fh)
                    self._dissect_fs = vol
                    self._dissect_fs_type = partition.filesystem
                    self._extractor = None
                    logger.info(
                        f"Selected partition {index}: {partition.filesystem} at offset {partition.offset} "
                        f"(pyfshfs HFS+ extraction enabled)"
                    )
                except Exception as e:
                    logger.error(f"pyfshfs failed to open HFS+ at partition {index}: {e}")
                    self._dissect_fs = None
                    self._dissect_fs_type = None
                    self._extractor = None

        else:
            self._extractor = None
            logger.warning(f"Unsupported filesystem: {partition.filesystem}")

        # Initialize cache
        self._path_cache.clear()
        self._parent_index_built = False
        self._parent_child_index.clear()
        self._name_to_inode_map.clear()

    def find_windows_partition(self) -> Optional[int]:
        """
        Find Windows system partition (excluding BitLocker)

        Finds NTFS partition with Windows installed,
        excluding Recovery and BitLocker encrypted partitions.

        Returns:
            Partition index or None

        Note:
            - Skips BitLocker encrypted partitions
            - Skips Recovery partitions (< 50GB)
            - Returns the largest NTFS partition
        """
        candidates = []

        for i, p in enumerate(self._partitions):
            # Exclude BitLocker
            if p.filesystem == 'BitLocker':
                logger.info(f"Partition {i}: BitLocker encrypted - skipping")
                continue

            # Consider NTFS only
            if p.filesystem != 'NTFS':
                continue

            # Exclude Recovery partition (usually under 50GB)
            size_gb = p.size / (1024 * 1024 * 1024)
            if size_gb < 50:
                # Check if Recovery
                if 'Recovery' in p.name or 'recovery' in p.type_name.lower():
                    logger.info(f"Partition {i}: Recovery partition - skipping")
                    continue

            candidates.append((i, p.size))

        if not candidates:
            logger.warning("No suitable Windows partition found")
            return None

        # Select largest partition
        candidates.sort(key=lambda x: x[1], reverse=True)
        best_idx = candidates[0][0]

        logger.info(f"Found Windows partition at index {best_idx}")
        return best_idx

    def has_bitlocker_partitions(self) -> bool:
        """Check if BitLocker encrypted partitions exist"""
        return any(p.filesystem == 'BitLocker' for p in self._partitions)

    def get_selected_partition(self) -> Optional[PartitionInfo]:
        """Return selected partition info"""
        if self._selected_partition is None:
            return None
        return self._partitions[self._selected_partition]

    # ==========================================================================
    # File Operations
    # ==========================================================================

    def read_file(self, path: str, max_size: int = None) -> bytes:
        """
        Read file by path

        Args:
            path: File path (e.g., "/Windows/System32/config/SYSTEM")
            max_size: Maximum read size

        Returns:
            File content (bytes)

        Raises:
            FilesystemError: File not found
        """
        # dissect path (non-NTFS)
        if self._dissect_fs is not None:
            return self._dissect_read_file_by_path(path, max_size=max_size)

        if self._extractor is None:
            raise FilesystemError("No partition selected or unsupported filesystem")

        # Normalize path
        path = self._normalize_path(path)

        # Find inode from cache
        if path in self._path_cache:
            return self._extractor.read_file_by_inode(self._path_cache[path], max_size=max_size)

        # Find file in MFT
        inode = self._resolve_path_to_inode(path)
        if inode is None:
            raise FilesystemError(f"File not found: {path}")

        self._path_cache[path] = inode
        return self._extractor.read_file_by_inode(inode, max_size=max_size)

    def read_file_by_inode(
        self,
        inode: int,
        stream_name: str = None,
        max_size: int = None
    ) -> bytes:
        """
        Read file by inode/MFT entry number

        Args:
            inode: MFT entry number (NTFS) or inode number (other filesystems)
            stream_name: ADS name (e.g., "Zone.Identifier") - NTFS only
            max_size: Maximum read size

        Returns:
            File content (bytes)
        """
        # dissect path (non-NTFS)
        if self._dissect_fs is not None:
            return self._dissect_read_file_by_inode(inode, max_size=max_size)

        if self._extractor is None:
            raise FilesystemError("No partition selected or unsupported filesystem")

        return self._extractor.read_file_by_inode(inode, stream_name=stream_name, max_size=max_size)

    def stream_file(
        self,
        path: str,
        chunk_size: int = 64 * 1024 * 1024
    ) -> Generator[bytes, None, None]:
        """
        Stream large file

        Args:
            path: File path
            chunk_size: Chunk size (default 64MB)

        Yields:
            File data chunks
        """
        # dissect path (non-NTFS)
        if self._dissect_fs is not None:
            yield from self._dissect_stream_file_by_path(path, chunk_size=chunk_size)
            return

        if self._extractor is None:
            raise FilesystemError("No partition selected")

        path = self._normalize_path(path)
        inode = self._resolve_path_to_inode(path)

        if inode is None:
            raise FilesystemError(f"File not found: {path}")

        yield from self._extractor.stream_file_by_inode(inode, chunk_size=chunk_size)

    def stream_file_by_inode(
        self,
        inode: int,
        stream_name: str = None,
        chunk_size: int = 64 * 1024 * 1024
    ) -> Generator[bytes, None, None]:
        """
        Stream large file by inode/MFT entry

        Args:
            inode: MFT entry number (NTFS) or inode number (other filesystems)
            stream_name: ADS name - NTFS only
            chunk_size: Chunk size

        Yields:
            File data chunks
        """
        # dissect path (non-NTFS)
        if self._dissect_fs is not None:
            yield from self._dissect_stream_file_by_inode(inode, chunk_size=chunk_size)
            return

        if self._extractor is None:
            raise FilesystemError("No partition selected")

        yield from self._extractor.stream_file_by_inode(inode, stream_name, chunk_size)

    def get_file_metadata(self, inode: int) -> FileMetadata:
        """
        Get file metadata

        Args:
            inode: MFT entry number (NTFS) or inode number (other filesystems)

        Returns:
            FileMetadata object
        """
        # dissect path (non-NTFS)
        if self._dissect_fs is not None:
            return self._dissect_get_file_metadata(inode)

        if self._extractor is None:
            raise FilesystemError("No partition selected")

        return self._extractor.get_file_metadata(inode)

    def list_ads_streams(self, inode: int) -> List[str]:
        """
        List file's ADS streams

        Args:
            inode: MFT entry number

        Returns:
            List of ADS names (e.g., ["Zone.Identifier", "encryptable"])
            Returns empty list for non-NTFS filesystems (ADS is NTFS-only)
        """
        # dissect path (non-NTFS) - ADS does not exist
        if self._dissect_fs is not None:
            return []

        if self._extractor is None:
            raise FilesystemError("No partition selected")

        return self._extractor.list_ads_streams(inode)

    def path_exists(self, path: str) -> bool:
        """
        Check if path exists

        Args:
            path: File/directory path

        Returns:
            Existence status
        """
        # dissect path (non-NTFS)
        if self._dissect_fs is not None:
            try:
                dissect_path = self._normalize_dissect_path(path)
                if self._dissect_fs_type in _HFS_FILESYSTEMS:
                    self._dissect_fs.get_file_entry_by_path(dissect_path)
                else:
                    self._dissect_fs.get(dissect_path)
                return True
            except Exception:
                return False

        if self._extractor is None:
            return False

        try:
            path = self._normalize_path(path)
            inode = self._resolve_path_to_inode(path)
            return inode is not None
        except Exception:
            return False

    def is_directory(self, path: str) -> bool:
        """
        Check if path is a directory

        Args:
            path: Path

        Returns:
            Whether it is a directory
        """
        # dissect path (non-NTFS)
        if self._dissect_fs is not None:
            try:
                dissect_path = self._normalize_dissect_path(path)
                if self._dissect_fs_type in _HFS_FILESYSTEMS:
                    node = self._dissect_fs.get_file_entry_by_path(dissect_path)
                else:
                    node = self._dissect_fs.get(dissect_path)
                return _node_is_dir(node, self._dissect_fs_type)
            except Exception:
                return False

        if self._extractor is None:
            return False

        try:
            path = self._normalize_path(path)
            inode = self._resolve_path_to_inode(path)
            if inode is None:
                return False

            metadata = self._extractor.get_file_metadata(inode)
            return metadata.is_directory
        except Exception:
            return False

    def _get_mft_entry_count(self) -> int:
        """
        Estimate total MFT entry count

        Calculates total entry count based on $MFT file size.
        """
        try:
            # Get size from $MFT metadata
            mft_metadata = self._extractor.get_file_metadata(0)
            if mft_metadata and mft_metadata.size > 0:
                # MFT entry size is typically 1024 bytes
                entry_count = mft_metadata.size // 1024
                logger.debug(f"MFT size: {mft_metadata.size} bytes, estimated entries: {entry_count}")
                return entry_count
        except Exception as e:
            logger.debug(f"Failed to get MFT size: {e}")

        # Default: 5 million entries (supports large images)
        return 5000000

    def _build_parent_index(self) -> None:
        """
        Build MFT parent-child index (runs only once)

        Traverses the entire MFT to create a parent_inode -> [child_inodes] map.
        Subsequent list_directory() calls can look up children in O(1).

        Also builds a filename -> inode map to support case-insensitive search.

        Digital forensics principles:
        - No MFT entry count limit (dynamically detects total size)
        - Only indexes non-deleted files (for list_directory)
        """
        if self._parent_index_built or self._extractor is None:
            return

        logger.info("Building MFT parent-child index (this may take a moment)...")
        self._parent_child_index = {}
        self._name_to_inode_map = {}  # (parent_inode, lowercase_name) -> inode

        try:
            # Full MFT traversal - dynamic size detection (no limit)
            max_entries = self._get_mft_entry_count()
            logger.info(f"MFT index building: scanning up to {max_entries:,} entries")

            # Preload entire $MFT into memory for fast scanning
            mft_preloaded = self._extractor.preload_mft()

            consecutive_errors = 0
            max_consecutive_errors = 1000
            indexed_count = 0

            for entry_num in range(0, max_entries):
                try:
                    entry_data = self._extractor.read_mft_entry(entry_num)

                    # Skip invalid entries
                    if entry_data[:4] != b'FILE':
                        consecutive_errors += 1
                        if consecutive_errors > max_consecutive_errors:
                            logger.debug(f"Stopping index build at entry {entry_num} due to consecutive errors")
                            break
                        continue

                    consecutive_errors = 0
                    metadata = self._extractor.get_file_metadata(entry_num, entry_data=entry_data)

                    # Only add non-deleted items to index
                    if not metadata.is_deleted:
                        parent = metadata.parent_ref
                        if parent not in self._parent_child_index:
                            self._parent_child_index[parent] = []
                        self._parent_child_index[parent].append(entry_num)

                        # Add to filename map (for case-insensitive search)
                        key = (parent, metadata.filename.lower())
                        self._name_to_inode_map[key] = entry_num
                        indexed_count += 1

                except Exception:
                    consecutive_errors += 1
                    if consecutive_errors > max_consecutive_errors:
                        break
                    continue

            if mft_preloaded:
                self._extractor.release_mft_preload()

            self._parent_index_built = True
            logger.info(f"MFT parent-child index built: {len(self._parent_child_index)} parent directories, {indexed_count} files indexed")

        except Exception as e:
            logger.warning(f"Failed to build parent index: {e}")
            self._parent_child_index = {}
            self._name_to_inode_map = {}

    def list_directory(self, path: str) -> List[FileCatalogEntry]:
        """
        List directory contents

        NTFS: index-based O(1) lookup via MFT parent-child index.
        Non-NTFS: dissect directory listing.

        Args:
            path: Directory path

        Returns:
            List of FileCatalogEntry
        """
        # dissect path (non-NTFS)
        if self._dissect_fs is not None:
            return self._dissect_list_directory(path)

        if self._extractor is None:
            return []

        try:
            path = self._normalize_path(path)
            dir_inode = self._resolve_path_to_inode(path)
            if dir_inode is None:
                return []

            # Build parent-child index if not exists (first time only)
            if not self._parent_index_built:
                self._build_parent_index()

            # Look up child inode list from index (O(1))
            child_inodes = self._parent_child_index.get(dir_inode, [])

            results = []
            for entry_num in child_inodes:
                try:
                    metadata = self._extractor.get_file_metadata(entry_num)

                    # Add only non-deleted items
                    if not metadata.is_deleted:
                        results.append(FileCatalogEntry(
                            inode=entry_num,
                            filename=metadata.filename,
                            full_path=f"{path}/{metadata.filename}",
                            size=metadata.size,
                            is_directory=metadata.is_directory,
                            is_deleted=metadata.is_deleted,
                            parent_inode=metadata.parent_ref,
                            created_time=metadata.created_time,
                            modified_time=metadata.modified_time,
                            has_data_runs=len(metadata.data_runs) > 0 or metadata.is_resident
                        ))
                except Exception:
                    continue

            return results
        except Exception as e:
            logger.debug(f"Failed to list directory {path}: {e}")
            return []

    # ==========================================================================
    # File System Scanning
    # ==========================================================================

    def scan_all_files(
        self,
        include_deleted: bool = True,
        max_entries: int = None,
        progress_callback=None
    ) -> Dict[str, Any]:
        """
        Full filesystem scan (including deleted files)

        NTFS: MFT-based scan with full metadata.
        Non-NTFS: dissect-based recursive directory walk.

        Digital forensics principles:
        - include_deleted=True (default): Include deleted files
        - max_entries=None (default): No limit, scan entire filesystem

        Args:
            include_deleted: Include deleted files (default: True)
            max_entries: Maximum entries to scan (default: None=no limit)
            progress_callback: Progress callback (current, total)

        Returns:
            {
                'total_entries': int,
                'active_files': List[FileCatalogEntry],
                'deleted_files': List[FileCatalogEntry],
                'directories': List[FileCatalogEntry],
                'special_files': Dict[str, int],  # inode for $MFT, $LogFile, etc. (NTFS only)
            }
        """
        # dissect path (non-NTFS)
        if self._dissect_fs is not None:
            return self._dissect_scan_all_files(
                include_deleted=include_deleted,
                max_entries=max_entries,
                progress_callback=progress_callback
            )

        if self._extractor is None:
            raise FilesystemError("No partition selected")

        result = {
            'total_entries': 0,
            'active_files': [],
            'deleted_files': [],
            'directories': [],
            'special_files': {},
            'errors': []
        }

        # inode -> (parent_inode, filename) mapping (for full_path calculation)
        inode_info: Dict[int, Tuple[int, str]] = {}

        # Estimate MFT size (from entry 0)
        entry_0 = self._extractor.read_mft_entry(0)
        if entry_0[:4] != b'FILE':
            return result

        # Calculate total MFT entry count (dynamic)
        total_mft_entries = self._get_mft_entry_count()
        if max_entries:
            total_mft_entries = min(total_mft_entries, max_entries)

        logger.info(f"Scanning MFT: {total_mft_entries:,} entries (max)")

        # Preload entire $MFT into memory for fast scanning
        # (critical for BitLocker decrypted volumes -- avoids per-entry AES decryption)
        mft_preloaded = self._extractor.preload_mft()

        # Traverse MFT entries
        entry_num = 0
        skip_count = 0  # Count of skipped empty entries

        while entry_num < total_mft_entries:
            try:
                entry = self._extractor.read_mft_entry(entry_num)

                # Check if valid entry - skip empty entries (not an error)
                if entry[:4] != b'FILE':
                    skip_count += 1
                    entry_num += 1
                    continue
                result['total_entries'] += 1

                # Extract metadata (reuse already-read entry to avoid double decrypt)
                try:
                    metadata = self._extractor.get_file_metadata(entry_num, entry_data=entry)
                except Exception as e:
                    result['errors'].append((entry_num, str(e)))
                    entry_num += 1
                    continue

                # Store in inode -> (parent, name) map (for full_path calculation)
                inode_info[entry_num] = (metadata.parent_ref, metadata.filename)

                # Create catalog entry
                catalog_entry = FileCatalogEntry(
                    inode=entry_num,
                    filename=metadata.filename,
                    size=metadata.size,
                    is_directory=metadata.is_directory,
                    is_deleted=metadata.is_deleted,
                    parent_inode=metadata.parent_ref,
                    created_time=metadata.created_time,
                    modified_time=metadata.modified_time,
                    has_data_runs=len(metadata.data_runs) > 0 or metadata.is_resident,
                    ads_streams=metadata.ads_streams
                )

                # Special system files ($MFT, $LogFile, etc.)
                if metadata.filename.startswith('$') and entry_num < 24:
                    result['special_files'][metadata.filename] = entry_num
                elif metadata.is_directory:
                    result['directories'].append(catalog_entry)
                elif metadata.is_deleted:
                    if include_deleted:
                        result['deleted_files'].append(catalog_entry)
                else:
                    result['active_files'].append(catalog_entry)

                # Progress callback
                if progress_callback and entry_num % 1000 == 0:
                    progress_callback(entry_num, max_entries or entry_num)

            except Exception as e:
                result['errors'].append((entry_num, str(e)))
                # Continue even on error (digital forensics principle: complete collection)

            entry_num += 1

        # Release preloaded MFT to free memory (parsed metadata is kept)
        if mft_preloaded:
            self._extractor.release_mft_preload()

        logger.info(f"Scanned {entry_num:,} MFT entries ({skip_count:,} empty/invalid skipped): "
                   f"{len(result['active_files'])} files, "
                   f"{len(result['directories'])} directories, "
                   f"{len(result['deleted_files'])} deleted")

        # Calculate full_path (build path by following inode chain)
        def build_full_path(inode: int, max_depth: int = 50) -> str:
            """Build full path from inode"""
            parts = []
            current = inode
            depth = 0
            while current in inode_info and depth < max_depth:
                parent, name = inode_info[current]
                # [2026-01] Include system folders like $Recycle.Bin in path
                # NTFS reserved files (inode 0-23) are already separated into special_files
                if name:
                    parts.append(name)
                if parent == current or parent == 5:  # Reached root
                    break
                current = parent
                depth += 1
            parts.reverse()
            return '/'.join(parts) if parts else ""

        # Set full_path for active_files and deleted_files
        for entry in result['active_files']:
            entry.full_path = build_full_path(entry.inode)

        for entry in result['deleted_files']:
            entry.full_path = build_full_path(entry.inode)

        for entry in result['directories']:
            entry.full_path = build_full_path(entry.inode)

        return result

    def find_files_by_name(
        self,
        name_pattern: str,
        include_deleted: bool = True,
        max_results: int = 100
    ) -> List[FileCatalogEntry]:
        """
        Search files by name

        Args:
            name_pattern: Filename pattern (case-insensitive)
            include_deleted: Include deleted files
            max_results: Maximum number of results

        Returns:
            List of FileCatalogEntry
        """
        # dissect path (non-NTFS) -- do a full scan and filter
        if self._dissect_fs is not None:
            return self._dissect_find_files_by_name(
                name_pattern, include_deleted, max_results
            )

        results = []
        name_lower = name_pattern.lower()
        entry_num = 0
        errors = 0

        while len(results) < max_results:
            try:
                metadata = self._extractor.get_file_metadata(entry_num)

                if metadata.filename.lower().find(name_lower) >= 0:
                    if not metadata.is_deleted or include_deleted:
                        results.append(FileCatalogEntry(
                            inode=entry_num,
                            filename=metadata.filename,
                            size=metadata.size,
                            is_directory=metadata.is_directory,
                            is_deleted=metadata.is_deleted,
                            parent_inode=metadata.parent_ref,
                            has_data_runs=len(metadata.data_runs) > 0
                        ))
                errors = 0
            except Exception:
                errors += 1
                if errors > 1000:
                    break

            entry_num += 1

        return results

    # ==========================================================================
    # Path Resolution
    # ==========================================================================

    def _normalize_path(self, path: str) -> str:
        """Normalize path"""
        # Convert backslashes to forward slashes
        path = path.replace('\\', '/')

        # Remove drive letter (C:/)
        if len(path) > 2 and path[1] == ':':
            path = path[2:]

        # Remove leading slashes
        while path.startswith('/'):
            path = path[1:]

        return path

    def _resolve_path_to_inode(self, path: str) -> Optional[int]:
        """Convert path to MFT entry number"""
        if not path:
            return 5  # Root directory

        parts = path.split('/')
        current_inode = 5  # Root directory is always entry 5

        for part in parts:
            if not part:
                continue

            # Find file in current directory's index
            found = self._find_in_directory(current_inode, part)
            if found is None:
                return None
            current_inode = found

        return current_inode

    def _find_in_directory(self, dir_inode: int, name: str) -> Optional[int]:
        """
        Find file in directory (using index - case-insensitive)

        Uses filename map for O(1) lookup.
        Ignores case.
        """
        name_lower = name.lower()

        # Build parent-child index if not exists (first time only)
        if not self._parent_index_built:
            self._build_parent_index()

        # Direct lookup from filename map (O(1))
        if hasattr(self, '_name_to_inode_map'):
            key = (dir_inode, name_lower)
            if key in self._name_to_inode_map:
                return self._name_to_inode_map[key]

        # Get child inode list from index
        child_inodes = self._parent_child_index.get(dir_inode, [])

        # Match filename in child list (case-insensitive)
        for entry_num in child_inodes:
            try:
                metadata = self._extractor.get_file_metadata(entry_num)
                if metadata.filename.lower() == name_lower:
                    # Update cache
                    if hasattr(self, '_name_to_inode_map'):
                        self._name_to_inode_map[(dir_inode, name_lower)] = entry_num
                    return entry_num
            except Exception:
                continue

        # If still not found, limited fallback (10,000 only)
        logger.debug(f"File '{name}' not found in index for dir_inode={dir_inode}")
        return None

    # ==========================================================================
    # dissect-based Methods (non-NTFS filesystem support)
    # ==========================================================================

    @staticmethod
    def _normalize_dissect_path(path: str) -> str:
        """
        Normalize a user-supplied path for dissect consumption.

        dissect filesystem .get() expects forward-slash paths with a leading
        slash and no drive letter prefix (e.g. "/etc/passwd").
        FAT uses backslash internally but dissect.fat.FATFS.get() converts
        / to \\ automatically.
        """
        # Backslash -> forward slash
        path = path.replace('\\', '/')
        # Remove drive letter (C:/)
        if len(path) > 2 and path[1] == ':':
            path = path[2:]
        # Ensure leading slash
        if not path.startswith('/'):
            path = '/' + path
        # Remove trailing slash (except root)
        if len(path) > 1 and path.endswith('/'):
            path = path.rstrip('/')
        return path

    def _dissect_node_to_catalog(
        self,
        node,
        filename: str,
        parent_path: str,
        parent_inode: int = 0
    ) -> Optional[FileCatalogEntry]:
        """
        Convert a dissect filesystem node into a FileCatalogEntry.

        Returns None if the entry should be skipped (e.g. '.' / '..').
        """
        try:
            # Use provided filename or extract from node
            if not filename:
                filename = _node_filename(node, self._dissect_fs_type)
            # Strip trailing slash from directory names
            filename = filename.rstrip('/')

            # Skip . and ..
            if filename in ('.', '..', '', './', '../'):
                return None

            inum = _node_inum(node, self._dissect_fs_type)
            size = _node_size(node)
            is_dir = _node_is_dir(node, self._dissect_fs_type)
            is_deleted = _node_is_deleted(node, self._dissect_fs_type)
            created, modified, accessed, changed = _node_timestamps(
                node, self._dissect_fs_type
            )

            full_path = f"{parent_path}/{filename}" if parent_path else filename

            return FileCatalogEntry(
                inode=inum,
                filename=filename,
                full_path=full_path,
                size=size,
                is_directory=is_dir,
                is_deleted=is_deleted,
                parent_inode=parent_inode,
                created_time=created,
                modified_time=modified,
                has_data_runs=(not is_dir and size > 0),
                ads_streams=[]
            )
        except Exception as e:
            logger.debug(f"Failed to convert dissect entry: {e}")
            return None

    def _dissect_iter_directory(self, node):
        """
        Iterate over directory entries of a dissect node.

        Yields (filename, child_node) tuples.  Handles the API differences
        between ExtFS/XFS (iterdir yields INode with .filename), FATFS
        (iterdir yields DirectoryEntry with .name), Btrfs (iterdir yields
        (name, INode) tuples), and FFS (iterdir yields INode with .name).
        """
        fs_type = self._dissect_fs_type

        # ExFAT has a dict-based structure, not iterdir
        if fs_type == 'exFAT':
            yield from self._dissect_iter_exfat_directory(node)
            return

        try:
            # HFS+/HFSX (pyfshfs): iterate sub_file_entries
            if fs_type in _HFS_FILESYSTEMS:
                for i in range(node.number_of_sub_file_entries):
                    try:
                        child = node.get_sub_file_entry(i)
                        fname = child.name if child.name else ""
                        if fname in ('.', '..', '', './', '../'):
                            continue
                        yield (fname, child)
                    except Exception:
                        continue
                return

            # Btrfs iterdir yields (name, child_node) tuples
            if fs_type == 'Btrfs':
                for name, child_node in node.iterdir():
                    if name in ('.', '..'):
                        continue
                    yield (name, child_node)
                return

            # ExtFS, XFS, FATFS, FFS -- iterdir yields node objects
            for child in node.iterdir():
                fname = _node_filename(child, fs_type)
                if fname in ('.', '..', '', './', '../'):
                    continue
                yield (fname, child)

        except Exception as e:
            logger.debug(f"[{fs_type}] Failed to iterate directory: {e}")

    def _dissect_iter_exfat_directory(self, node_or_dict):
        """
        Iterate over ExFAT directory entries.

        ExFAT stores files in an OrderedDict: { filename: (file_entry, sub_dict_or_None) }
        Directories have sub_dict != None.
        """
        # The ExFAT root is stored as self._dissect_fs.files (an OrderedDict)
        # For subdirectories, the second element of the tuple is the sub-dict.
        if isinstance(node_or_dict, dict):
            entries = node_or_dict
        elif hasattr(node_or_dict, 'files'):
            entries = node_or_dict.files
        else:
            return

        for filename, value in entries.items():
            if isinstance(value, tuple) and len(value) == 2:
                file_entry, sub_dict = value
                yield (filename.rstrip('/'), (file_entry, sub_dict))
            else:
                yield (filename.rstrip('/'), value)

    # ---------- scan_all_files (dissect) ----------

    _ORPHAN_SCAN_MAX_INODES = 100_000
    _ORPHAN_SCAN_MAX_RESULTS = 5_000

    def _dissect_scan_all_files(
        self,
        include_deleted: bool = True,
        max_entries: int = None,
        progress_callback=None
    ) -> Dict[str, Any]:
        """
        Recursively walk the filesystem tree via dissect and return the
        same dict structure as the NTFS MFT-based scan_all_files().

        Unlike pytsk3, dissect uses pure Python objects and does not have
        C memory lifecycle issues.  The walk is still done iteratively to
        control memory and support timeout/progress.
        """
        import time as _time

        result: Dict[str, Any] = {
            'total_entries': 0,
            'active_files': [],
            'deleted_files': [],
            'directories': [],
            'special_files': {},
            'errors': []
        }

        entry_count = 0
        limit = max_entries or float('inf')
        _scan_start = _time.monotonic()
        _SCAN_TIMEOUT = 600  # 10 minutes max for directory walk
        _IO_THROTTLE_INTERVAL = 5000

        fs_type = self._dissect_fs_type

        # ExFAT requires special handling (dict-based)
        if fs_type == 'exFAT':
            self._dissect_scan_exfat(result, limit, _scan_start, _SCAN_TIMEOUT,
                                      include_deleted, progress_callback)
            return result

        def _walk(node, parent_path: str, parent_inode: int):
            nonlocal entry_count

            if _time.monotonic() - _scan_start > _SCAN_TIMEOUT:
                logger.warning(f"[{fs_type}] Scan timeout ({_SCAN_TIMEOUT}s) -- partial results returned")
                return

            # Collect child directories for deferred recursion
            child_dirs = []

            try:
                for fname, child_node in self._dissect_iter_directory(node):
                    if entry_count >= limit:
                        break
                    if entry_count % 1000 == 0 and _time.monotonic() - _scan_start > _SCAN_TIMEOUT:
                        break

                    catalog = self._dissect_node_to_catalog(
                        child_node, fname, parent_path, parent_inode
                    )
                    if catalog is None:
                        continue

                    entry_count += 1
                    result['total_entries'] += 1

                    if catalog.is_directory:
                        result['directories'].append(catalog)
                        child_dirs.append((child_node, catalog.inode, catalog.full_path))
                    elif catalog.is_deleted:
                        if include_deleted:
                            result['deleted_files'].append(catalog)
                    else:
                        result['active_files'].append(catalog)

                    if entry_count % _IO_THROTTLE_INTERVAL == 0:
                        if progress_callback:
                            progress_callback(entry_count, max_entries or entry_count)
                        _time.sleep(0.01)

            except Exception as e:
                result['errors'].append((parent_inode, f"readdir: {e}"))

            # Phase 2: Recurse into child directories
            for child_node, child_inum, child_path in child_dirs:
                if entry_count >= limit:
                    return
                if _time.monotonic() - _scan_start > _SCAN_TIMEOUT:
                    return
                try:
                    _walk(child_node, child_path, child_inum)
                except Exception as e:
                    result['errors'].append(
                        (child_inum, f"opendir {child_path}: {e}")
                    )

        # Start walk from root
        try:
            if fs_type in _HFS_FILESYSTEMS:
                root = self._dissect_fs.get_root_directory()
            else:
                root = self._dissect_fs.get("/")
            _walk(root, "", 0)
        except Exception as e:
            logger.error(f"[{fs_type}] Root directory open failed: {e}")
            result['errors'].append((0, f"root: {e}"))

        # If include_deleted, try to recover orphan files via inode scan
        # SAFETY: Skip orphan scan for virtual disk backends
        if include_deleted:
            _skip_orphan = False
            try:
                from collectors.forensic_disk.disk_backends import (
                    VMDKDiskBackend, VHDDiskBackend, VHDXDiskBackend,
                    QCOW2DiskBackend, VDIDiskBackend
                )
                _virtual_backends = (VMDKDiskBackend, VHDDiskBackend, VHDXDiskBackend,
                                     QCOW2DiskBackend, VDIDiskBackend)
                if isinstance(self._backend, _virtual_backends):
                    _skip_orphan = True
                    logger.info(
                        f"[{fs_type}] Skipping orphan inode scan on virtual disk "
                        f"(prevents system freeze from random I/O on large images)"
                    )
            except ImportError:
                pass

            if not _skip_orphan:
                orphans = self._dissect_scan_orphan_files(
                    result, entry_count, max_entries
                )
                entry_count += orphans

        logger.info(
            f"[{fs_type}] dissect scan complete: "
            f"{len(result['active_files'])} files, "
            f"{len(result['directories'])} directories, "
            f"{len(result['deleted_files'])} deleted, "
            f"{len(result['errors'])} errors"
        )

        return result

    def _dissect_scan_exfat(
        self,
        result: Dict[str, Any],
        limit: float,
        scan_start: float,
        scan_timeout: float,
        include_deleted: bool,
        progress_callback
    ):
        """
        Walk the ExFAT dict-based filesystem tree.

        ExFAT files are stored as: { filename: (FILE_entry, sub_dict_or_None) }
        """
        import time as _time

        entry_count = 0
        fs_type = self._dissect_fs_type

        def _walk_dict(entries: dict, parent_path: str, parent_inode: int):
            nonlocal entry_count

            if _time.monotonic() - scan_start > scan_timeout:
                return

            child_dirs = []

            for filename, value in entries.items():
                if entry_count >= limit:
                    break
                if _time.monotonic() - scan_start > scan_timeout:
                    break

                filename = filename.rstrip('/')
                if filename in ('.', '..', ''):
                    continue

                # value is (FILE_entry, sub_dict_or_None)
                if isinstance(value, tuple) and len(value) == 2:
                    file_entry, sub_dict = value
                else:
                    file_entry = value
                    sub_dict = None

                is_dir = sub_dict is not None
                size = 0
                created = 0
                modified = 0
                cluster = 0

                try:
                    if hasattr(file_entry, 'stream') and hasattr(file_entry.stream, 'data_length'):
                        size = int(file_entry.stream.data_length)
                    if hasattr(file_entry, 'metadata'):
                        md = file_entry.metadata
                        if hasattr(md, 'create_timestamp'):
                            created = int(md.create_timestamp) if md.create_timestamp else 0
                        if hasattr(md, 'modify_timestamp'):
                            modified = int(md.modify_timestamp) if md.modify_timestamp else 0
                    if hasattr(file_entry, 'stream') and hasattr(file_entry.stream, 'first_cluster'):
                        cluster = int(file_entry.stream.first_cluster)
                except Exception:
                    pass

                full_path = f"{parent_path}/{filename}" if parent_path else filename

                catalog_entry = FileCatalogEntry(
                    inode=cluster,
                    filename=filename,
                    full_path=full_path,
                    size=size,
                    is_directory=is_dir,
                    is_deleted=False,
                    parent_inode=parent_inode,
                    created_time=created,
                    modified_time=modified,
                    has_data_runs=(not is_dir and size > 0),
                    ads_streams=[]
                )

                entry_count += 1
                result['total_entries'] += 1

                if is_dir:
                    result['directories'].append(catalog_entry)
                    child_dirs.append((sub_dict, cluster, full_path))
                else:
                    result['active_files'].append(catalog_entry)

                if progress_callback and entry_count % 1000 == 0:
                    progress_callback(entry_count, entry_count)

            # Recurse into subdirectories
            for sub_dict, child_inum, child_path in child_dirs:
                if entry_count >= limit:
                    return
                if sub_dict:
                    _walk_dict(sub_dict, child_path, child_inum)

        try:
            root_files = self._dissect_fs.files
            # root_files is {"/" : (root_FILE, sub_dict_of_root_contents)}
            for key, value in root_files.items():
                if isinstance(value, tuple) and len(value) == 2:
                    _, root_contents = value
                    if isinstance(root_contents, dict):
                        _walk_dict(root_contents, "", 0)
                        break
        except Exception as e:
            logger.error(f"[{fs_type}] ExFAT root scan failed: {e}")
            result['errors'].append((0, f"exfat root: {e}"))

    def _dissect_scan_orphan_files(
        self,
        result: Dict[str, Any],
        current_count: int,
        max_entries: Optional[int]
    ) -> int:
        """
        Attempt to find deleted/orphan files that are no longer in any
        directory listing by scanning inodes directly.

        This catches files whose parent directory entry has been removed
        but whose inode metadata is still intact (unallocated but readable).

        Safety limits (prevent system crash on large virtual disks):
        - Scans at most _ORPHAN_SCAN_MAX_INODES inodes (default 100K)
        - Collects at most _ORPHAN_SCAN_MAX_RESULTS orphan entries (default 5K)

        Returns the number of orphan entries found.
        """
        fs_type = self._dissect_fs_type
        fs_lower = fs_type.lower() if fs_type else ''

        # Only ext2/3/4 and UFS support inode-level access for orphan scanning.
        # FAT, exFAT, XFS, Btrfs don't expose unlinked inodes via dissect.
        if fs_lower not in ('ext2', 'ext3', 'ext4', 'ufs'):
            logger.debug(f"[{fs_type}] Orphan scan not supported for this filesystem type")
            return 0

        # Collect all inodes already seen from the directory walk
        seen_inodes = set()
        for lst in (result['active_files'], result['deleted_files'], result['directories']):
            for entry in lst:
                seen_inodes.add(entry.inode)

        scan_cap = self._ORPHAN_SCAN_MAX_INODES
        max_orphan_results = self._ORPHAN_SCAN_MAX_RESULTS
        limit = max_entries or float('inf')
        orphan_count = 0
        scanned_count = 0
        consecutive_errors = 0
        max_consecutive = 500

        # Determine inode range
        if fs_lower == 'ufs' and hasattr(self._dissect_fs, 'sb'):
            try:
                sb = self._dissect_fs.sb
                upper = min(sb.fs_ncg * sb.fs_ipg, 5_000_000)
            except Exception:
                upper = 100_000
        elif fs_lower.startswith('ext') and hasattr(self._dissect_fs, 'sb'):
            try:
                upper = min(int(self._dissect_fs.sb.s_inodes_count), 5_000_000)
            except Exception:
                upper = 100_000
        else:
            upper = 100_000

        logger.info(
            f"[{fs_type}] Orphan scan: inode range 2..{upper - 1:,}, "
            f"seen={len(seen_inodes):,}, scan cap={scan_cap:,}"
        )

        for inum in range(2, upper):
            if current_count + orphan_count >= limit:
                break
            if orphan_count >= max_orphan_results:
                logger.info(f"[{fs_type}] Orphan scan hit result cap ({max_orphan_results:,}), stopping")
                break
            if inum in seen_inodes:
                continue

            scanned_count += 1
            if scanned_count > scan_cap:
                logger.info(f"[{fs_type}] Orphan scan hit inode cap ({scan_cap:,} probed), stopping")
                break

            try:
                if fs_lower.startswith('ext'):
                    node = self._dissect_fs.get_inode(inum)
                elif fs_lower == 'ufs':
                    node = self._dissect_fs.inode(inum)
                else:
                    continue

                # Check if deleted
                is_deleted = _node_is_deleted(node, fs_type)
                if not is_deleted:
                    consecutive_errors = 0
                    continue

                is_dir = _node_is_dir(node, fs_type)
                size = _node_size(node)

                # Skip zero-size deleted entries and deleted dirs (noise)
                if size == 0 or is_dir:
                    consecutive_errors = 0
                    continue

                created, modified, accessed, changed = _node_timestamps(node, fs_type)

                entry = FileCatalogEntry(
                    inode=inum,
                    filename=f"<orphan-{inum}>",
                    full_path=f"$OrphanFiles/<orphan-{inum}>",
                    size=size,
                    is_directory=False,
                    is_deleted=True,
                    parent_inode=0,
                    created_time=created,
                    modified_time=modified,
                    has_data_runs=(size > 0),
                    ads_streams=[]
                )
                result['deleted_files'].append(entry)
                orphan_count += 1
                consecutive_errors = 0

            except Exception:
                consecutive_errors += 1
                if consecutive_errors > max_consecutive:
                    break
                continue

        if orphan_count > 0:
            logger.info(
                f"[{fs_type}] Found {orphan_count} orphan/deleted inodes "
                f"(probed {scanned_count:,} of {upper - 2:,} possible)"
            )

        return orphan_count

    # ---------- find_files_by_name (dissect) ----------

    def _dissect_find_files_by_name(
        self,
        name_pattern: str,
        include_deleted: bool = True,
        max_results: int = 100
    ) -> List[FileCatalogEntry]:
        """
        Search files by name via dissect recursive walk.
        """
        results: List[FileCatalogEntry] = []
        name_lower = name_pattern.lower()
        fs_type = self._dissect_fs_type

        # ExFAT special handling
        if fs_type == 'exFAT':
            return self._dissect_find_exfat_by_name(name_lower, include_deleted, max_results)

        def _walk(node, parent_path: str, parent_inode: int):
            if len(results) >= max_results:
                return

            try:
                for fname, child_node in self._dissect_iter_directory(node):
                    if len(results) >= max_results:
                        return

                    catalog = self._dissect_node_to_catalog(
                        child_node, fname, parent_path, parent_inode
                    )
                    if catalog is None:
                        continue

                    # Name match
                    if name_lower in catalog.filename.lower():
                        if not catalog.is_deleted or include_deleted:
                            results.append(catalog)

                    # Recurse into directories
                    if catalog.is_directory:
                        try:
                            _walk(child_node, catalog.full_path, catalog.inode)
                        except Exception:
                            continue
            except Exception:
                pass

        try:
            if fs_type in _HFS_FILESYSTEMS:
                root = self._dissect_fs.get_root_directory()
            else:
                root = self._dissect_fs.get("/")
            _walk(root, "", 0)
        except Exception as e:
            logger.debug(f"[{fs_type}] find_files_by_name failed: {e}")

        return results

    def _dissect_find_exfat_by_name(
        self,
        name_lower: str,
        include_deleted: bool,
        max_results: int
    ) -> List[FileCatalogEntry]:
        """Search files by name in ExFAT dict-based tree."""
        results = []

        def _walk_dict(entries: dict, parent_path: str, parent_inode: int):
            if len(results) >= max_results:
                return

            for filename, value in entries.items():
                if len(results) >= max_results:
                    return

                filename = filename.rstrip('/')
                if filename in ('.', '..', ''):
                    continue

                if isinstance(value, tuple) and len(value) == 2:
                    file_entry, sub_dict = value
                else:
                    file_entry = value
                    sub_dict = None

                is_dir = sub_dict is not None
                full_path = f"{parent_path}/{filename}" if parent_path else filename

                if name_lower in filename.lower():
                    size = 0
                    cluster = 0
                    try:
                        if hasattr(file_entry, 'stream') and hasattr(file_entry.stream, 'data_length'):
                            size = int(file_entry.stream.data_length)
                        if hasattr(file_entry, 'stream') and hasattr(file_entry.stream, 'first_cluster'):
                            cluster = int(file_entry.stream.first_cluster)
                    except Exception:
                        pass

                    results.append(FileCatalogEntry(
                        inode=cluster,
                        filename=filename,
                        full_path=full_path,
                        size=size,
                        is_directory=is_dir,
                        is_deleted=False,
                        parent_inode=parent_inode,
                        has_data_runs=(not is_dir and size > 0),
                        ads_streams=[]
                    ))

                if is_dir and sub_dict:
                    _walk_dict(sub_dict, full_path, cluster if 'cluster' in dir() else 0)

        try:
            root_files = self._dissect_fs.files
            for key, value in root_files.items():
                if isinstance(value, tuple) and len(value) == 2:
                    _, root_contents = value
                    if isinstance(root_contents, dict):
                        _walk_dict(root_contents, "", 0)
                        break
        except Exception as e:
            logger.debug(f"[exFAT] find_files_by_name failed: {e}")

        return results

    # ---------- list_directory (dissect) ----------

    def _dissect_list_directory(self, path: str) -> List[FileCatalogEntry]:
        """List directory contents via dissect."""
        fs_type = self._dissect_fs_type

        try:
            dissect_path = self._normalize_dissect_path(path)

            # ExFAT special handling
            if fs_type == 'exFAT':
                return self._dissect_list_exfat_directory(dissect_path)

            # HFS+/HFSX: use get_file_entry_by_path
            if fs_type in _HFS_FILESYSTEMS:
                node = self._dissect_fs.get_file_entry_by_path(dissect_path)
            else:
                node = self._dissect_fs.get(dissect_path)
            parent_inode = _node_inum(node, fs_type)
            parent_path = dissect_path.rstrip('/')

            results = []
            for fname, child_node in self._dissect_iter_directory(node):
                catalog = self._dissect_node_to_catalog(
                    child_node,
                    fname,
                    parent_path=parent_path,
                    parent_inode=parent_inode
                )
                if catalog is not None and not catalog.is_deleted:
                    results.append(catalog)

            return results
        except Exception as e:
            logger.debug(f"[{fs_type}] Failed to list directory '{path}': {e}")
            return []

    def _dissect_list_exfat_directory(self, path: str) -> List[FileCatalogEntry]:
        """List directory contents for ExFAT."""
        results = []
        try:
            # Navigate the dict tree to find the target directory
            parts = [p for p in path.split('/') if p]
            current_dict = None

            # Start from root
            root_files = self._dissect_fs.files
            for key, value in root_files.items():
                if isinstance(value, tuple) and len(value) == 2:
                    _, root_contents = value
                    if isinstance(root_contents, dict):
                        current_dict = root_contents
                        break

            if current_dict is None:
                return results

            # Navigate to target directory
            for part in parts:
                found = False
                for filename, value in current_dict.items():
                    if filename.rstrip('/').lower() == part.lower():
                        if isinstance(value, tuple) and len(value) == 2:
                            _, sub_dict = value
                            if isinstance(sub_dict, dict):
                                current_dict = sub_dict
                                found = True
                                break
                if not found:
                    return results

            # List entries in current directory
            for filename, value in current_dict.items():
                filename = filename.rstrip('/')
                if filename in ('.', '..', ''):
                    continue

                if isinstance(value, tuple) and len(value) == 2:
                    file_entry, sub_dict = value
                else:
                    file_entry = value
                    sub_dict = None

                is_dir = sub_dict is not None
                size = 0
                cluster = 0
                try:
                    if hasattr(file_entry, 'stream') and hasattr(file_entry.stream, 'data_length'):
                        size = int(file_entry.stream.data_length)
                    if hasattr(file_entry, 'stream') and hasattr(file_entry.stream, 'first_cluster'):
                        cluster = int(file_entry.stream.first_cluster)
                except Exception:
                    pass

                results.append(FileCatalogEntry(
                    inode=cluster,
                    filename=filename,
                    full_path=f"{path.rstrip('/')}/{filename}",
                    size=size,
                    is_directory=is_dir,
                    is_deleted=False,
                    parent_inode=0,
                    has_data_runs=(not is_dir and size > 0),
                    ads_streams=[]
                ))

        except Exception as e:
            logger.debug(f"[exFAT] Failed to list directory '{path}': {e}")

        return results

    # ---------- read_file (dissect) ----------

    def _dissect_read_file_content(self, node, max_size: int = None) -> bytes:
        """
        Read file content from a dissect filesystem node.

        Uses the node.open() method which returns a BinaryIO (file-like object).
        """
        size = _node_size(node)
        if size == 0:
            return b''

        read_size = size
        if max_size is not None and max_size < size:
            read_size = max_size

        try:
            fh = node.open()
            data = fh.read(read_size)
            return data
        except Exception as e:
            # Attempt chunked recovery for partially damaged files
            logger.debug(f"Full read failed ({e}), attempting chunked recovery")
            return self._dissect_read_file_chunked(node, read_size)

    def _dissect_read_file_chunked(
        self,
        node,
        total_size: int,
        chunk_size: int = 1024 * 1024
    ) -> bytes:
        """Best-effort chunked read for partially damaged files."""
        data = bytearray()
        try:
            fh = node.open()
            offset = 0
            while offset < total_size:
                try:
                    read_len = min(chunk_size, total_size - offset)
                    chunk = fh.read(read_len)
                    if not chunk:
                        break
                    data.extend(chunk)
                    offset += len(chunk)
                except Exception:
                    fill_len = min(chunk_size, total_size - offset)
                    data.extend(b'\x00' * fill_len)
                    offset += fill_len
        except Exception as e:
            logger.debug(f"Chunked read also failed: {e}")

        return bytes(data)

    def _dissect_read_file_by_path(self, path: str, max_size: int = None) -> bytes:
        """Read file content by path via dissect."""
        dissect_path = self._normalize_dissect_path(path)
        fs_type = self._dissect_fs_type

        # ExFAT special handling
        if fs_type == 'exFAT':
            return self._dissect_read_exfat_by_path(dissect_path, max_size)

        # HFS+/HFSX: use pyfshfs get_file_entry_by_path + read_buffer_at_offset
        if fs_type in _HFS_FILESYSTEMS:
            try:
                entry = self._dissect_fs.get_file_entry_by_path(dissect_path)
                size = entry.size if entry.size else 0
                if size == 0:
                    return b''
                read_size = min(size, max_size) if max_size else size
                entry.seek(0)
                return entry.read(read_size)
            except Exception as e:
                if 'unable to retrieve' in str(e).lower() or 'not found' in str(e).lower():
                    raise FilesystemError(f"File not found: {path}")
                raise FilesystemError(f"Failed to read file {path}: {e}")

        try:
            node = self._dissect_fs.get(dissect_path)
            return self._dissect_read_file_content(node, max_size)
        except FileNotFoundError:
            raise FilesystemError(f"File not found: {path}")
        except Exception as e:
            raise FilesystemError(f"Failed to read file {path}: {e}")

    def _dissect_read_exfat_by_path(self, path: str, max_size: int = None) -> bytes:
        """Read file content by path from ExFAT filesystem."""
        parts = [p for p in path.split('/') if p]
        if not parts:
            raise FilesystemError(f"Invalid path: {path}")

        try:
            # Navigate dict tree
            current_dict = None
            root_files = self._dissect_fs.files
            for key, value in root_files.items():
                if isinstance(value, tuple) and len(value) == 2:
                    _, root_contents = value
                    if isinstance(root_contents, dict):
                        current_dict = root_contents
                        break

            if current_dict is None:
                raise FilesystemError(f"File not found: {path}")

            # Navigate to parent directory
            for part in parts[:-1]:
                found = False
                for filename, value in current_dict.items():
                    if filename.rstrip('/').lower() == part.lower():
                        if isinstance(value, tuple) and len(value) == 2:
                            _, sub_dict = value
                            if isinstance(sub_dict, dict):
                                current_dict = sub_dict
                                found = True
                                break
                if not found:
                    raise FilesystemError(f"File not found: {path}")

            # Find the target file
            target = parts[-1]
            for filename, value in current_dict.items():
                if filename.rstrip('/').lower() == target.lower():
                    if isinstance(value, tuple) and len(value) == 2:
                        file_entry, _ = value
                    else:
                        file_entry = value

                    # Read via runlist stream
                    size = 0
                    if hasattr(file_entry, 'stream') and hasattr(file_entry.stream, 'data_length'):
                        size = int(file_entry.stream.data_length)
                    if size == 0:
                        return b''

                    read_size = min(size, max_size) if max_size else size

                    # Create runlist stream for reading
                    from dissect.fat.exfat import RunlistStream
                    runlist = self._dissect_fs.runlist(file_entry)
                    fh = RunlistStream(
                        self._dissect_fh, runlist, size,
                        self._dissect_fs.sector_size
                    )
                    return fh.read(read_size)

            raise FilesystemError(f"File not found: {path}")

        except FilesystemError:
            raise
        except Exception as e:
            raise FilesystemError(f"Failed to read file {path}: {e}")

    def _dissect_read_file_by_inode(self, inode: int, max_size: int = None) -> bytes:
        """Read file content by inode via dissect."""
        fs_type = self._dissect_fs_type

        # ExFAT does not support inode-based access
        if fs_type == 'exFAT':
            raise FilesystemError("ExFAT does not support inode-based file access. Use path-based access.")

        # HFS+/HFSX: use pyfshfs get_file_entry_by_identifier (CNID)
        if fs_type in _HFS_FILESYSTEMS:
            try:
                entry = self._dissect_fs.get_file_entry_by_identifier(inode)
                size = entry.size if entry.size else 0
                if size == 0:
                    return b''
                read_size = min(size, max_size) if max_size else size
                entry.seek(0)
                return entry.read(read_size)
            except Exception as e:
                if 'unable to retrieve' in str(e).lower() or 'not found' in str(e).lower():
                    raise FilesystemError(f"Inode not found: {inode}")
                raise FilesystemError(f"Failed to read inode {inode}: {e}")

        try:
            node = self._dissect_fs.get(inode)
            return self._dissect_read_file_content(node, max_size)
        except FileNotFoundError:
            raise FilesystemError(f"Inode not found: {inode}")
        except Exception as e:
            raise FilesystemError(f"Failed to read inode {inode}: {e}")

    # ---------- stream_file (dissect) ----------

    def _dissect_stream_file_content(
        self, node, chunk_size: int = 64 * 1024 * 1024
    ) -> Generator[bytes, None, None]:
        """Stream file content in chunks from a dissect filesystem node."""
        fs_type = self._dissect_fs_type
        size = _node_size(node)
        if size == 0:
            return

        # HFS+/HFSX (pyfshfs): use seek() + read() on the file_entry directly
        if fs_type in _HFS_FILESYSTEMS:
            try:
                offset = 0
                node.seek(0)
                while offset < size:
                    read_len = min(chunk_size, size - offset)
                    try:
                        chunk = node.read(read_len)
                        if not chunk:
                            break
                        yield chunk
                        offset += len(chunk)
                    except Exception as e:
                        logger.debug(f"HFS+ stream read error at offset {offset}: {e}")
                        yield b'\x00' * read_len
                        offset += read_len
            except Exception as e:
                logger.error(f"Failed to stream HFS+ file: {e}")
            return

        try:
            fh = node.open()
            offset = 0
            while offset < size:
                read_len = min(chunk_size, size - offset)
                try:
                    chunk = fh.read(read_len)
                    if not chunk:
                        break
                    yield chunk
                    offset += len(chunk)
                except Exception as e:
                    logger.debug(f"Stream read error at offset {offset}: {e}")
                    yield b'\x00' * read_len
                    offset += read_len
        except Exception as e:
            logger.error(f"Failed to open file for streaming: {e}")

    def _dissect_stream_file_by_path(
        self, path: str, chunk_size: int = 64 * 1024 * 1024
    ) -> Generator[bytes, None, None]:
        """Stream file content by path via dissect."""
        dissect_path = self._normalize_dissect_path(path)
        fs_type = self._dissect_fs_type

        if fs_type == 'exFAT':
            # For ExFAT, read the whole file and yield in chunks
            data = self._dissect_read_exfat_by_path(dissect_path)
            for i in range(0, len(data), chunk_size):
                yield data[i:i + chunk_size]
            return

        # HFS+/HFSX: use pyfshfs get_file_entry_by_path
        if fs_type in _HFS_FILESYSTEMS:
            try:
                entry = self._dissect_fs.get_file_entry_by_path(dissect_path)
                yield from self._dissect_stream_file_content(entry, chunk_size)
            except Exception as e:
                if 'unable to retrieve' in str(e).lower() or 'not found' in str(e).lower():
                    raise FilesystemError(f"File not found: {path}")
                raise FilesystemError(f"Failed to stream file {path}: {e}")
            return

        try:
            node = self._dissect_fs.get(dissect_path)
            yield from self._dissect_stream_file_content(node, chunk_size)
        except FileNotFoundError:
            raise FilesystemError(f"File not found: {path}")

    def _dissect_stream_file_by_inode(
        self, inode: int, chunk_size: int = 64 * 1024 * 1024
    ) -> Generator[bytes, None, None]:
        """Stream file content by inode via dissect."""
        if self._dissect_fs_type == 'exFAT':
            raise FilesystemError("ExFAT does not support inode-based file access.")

        # HFS+/HFSX: use pyfshfs get_file_entry_by_identifier (CNID)
        if self._dissect_fs_type in _HFS_FILESYSTEMS:
            try:
                entry = self._dissect_fs.get_file_entry_by_identifier(inode)
                yield from self._dissect_stream_file_content(entry, chunk_size)
            except Exception as e:
                if 'unable to retrieve' in str(e).lower() or 'not found' in str(e).lower():
                    raise FilesystemError(f"Inode not found: {inode}")
                raise FilesystemError(f"Failed to stream inode {inode}: {e}")
            return

        try:
            node = self._dissect_fs.get(inode)
            yield from self._dissect_stream_file_content(node, chunk_size)
        except FileNotFoundError:
            raise FilesystemError(f"Inode not found: {inode}")

    # ---------- get_file_metadata (dissect) ----------

    def _dissect_get_file_metadata(self, inode: int) -> FileMetadata:
        """
        Get file metadata from dissect by inode.

        Returns a FileMetadata object matching the same structure as
        NTFS MFT-based metadata.
        """
        fs_type = self._dissect_fs_type

        if fs_type == 'exFAT':
            raise FilesystemError("ExFAT does not support inode-based metadata lookup.")

        # HFS+/HFSX: use pyfshfs — accept both CNID (int) and path (str)
        if fs_type in _HFS_FILESYSTEMS:
            try:
                if isinstance(inode, str):
                    entry = self._dissect_fs.get_file_entry_by_path(inode)
                else:
                    entry = self._dissect_fs.get_file_entry_by_identifier(int(inode))
            except Exception as e:
                raise FilesystemError(f"Failed to open HFS+ entry {inode}: {e}")

            is_dir = _node_is_dir(entry, fs_type)
            size = entry.size if entry.size else 0
            filename = entry.name if entry.name else f"cnid-{inode}"
            created, modified, accessed, changed = _node_timestamps(entry, fs_type)
            parent_id = entry.parent_identifier if hasattr(entry, 'parent_identifier') else 0

            return FileMetadata(
                inode=inode,
                filename=filename,
                full_path="",  # Not resolvable from CNID alone
                size=size,
                allocated_size=size,
                is_directory=is_dir,
                is_deleted=False,  # pyfshfs does not expose deleted entries
                is_resident=False,
                resident_data=b'',
                data_runs=[],
                ads_streams=[],
                created_time=created,
                modified_time=modified,
                accessed_time=accessed,
                mft_changed_time=changed,
                parent_ref=parent_id,
                flags=0
            )

        try:
            node = self._dissect_fs.get(inode)
        except Exception as e:
            raise FilesystemError(f"Failed to open inode {inode}: {e}")

        is_dir = _node_is_dir(node, fs_type)
        is_deleted = _node_is_deleted(node, fs_type)
        size = _node_size(node)

        # Try to get the filename
        filename = _node_filename(node, fs_type)
        if not filename:
            filename = f"inode-{inode}"

        created, modified, accessed, changed = _node_timestamps(node, fs_type)

        return FileMetadata(
            inode=inode,
            filename=filename,
            full_path="",  # Not resolvable from inode alone
            size=size,
            allocated_size=size,
            is_directory=is_dir,
            is_deleted=is_deleted,
            is_resident=False,
            resident_data=b'',
            data_runs=[],  # dissect handles data runs internally
            ads_streams=[],  # ADS is NTFS-only
            created_time=created,
            modified_time=modified,
            accessed_time=accessed,
            mft_changed_time=changed,
            parent_ref=0,
            flags=0
        )

    # ==========================================================================
    # Special Files
    # ==========================================================================

    def read_mft_raw(self, max_size: int = None) -> bytes:
        """
        Read $MFT file raw data (NTFS only)

        Args:
            max_size: Maximum size (None = all)

        Returns:
            MFT raw data

        Raises:
            FilesystemError: Not an NTFS partition
        """
        if self._dissect_fs is not None:
            raise FilesystemError("$MFT is an NTFS-specific structure (current filesystem: "
                                  f"{self._dissect_fs_type})")
        return self.read_file_by_inode(0, max_size=max_size)

    def read_logfile_raw(self, max_size: int = None) -> bytes:
        """
        Read $LogFile raw data (NTFS transaction log, NTFS only)
        """
        if self._dissect_fs is not None:
            raise FilesystemError("$LogFile is an NTFS-specific structure (current filesystem: "
                                  f"{self._dissect_fs_type})")
        return self.read_file_by_inode(2, max_size=max_size)

    def read_usnjrnl_raw(self, max_size: int = None, skip_sparse: bool = True) -> bytes:
        """
        Read $UsnJrnl:$J raw data (USN Journal)

        $UsnJrnl entry number is not fixed - must be found in $Extend directory

        Args:
            max_size: Maximum read size
            skip_sparse: If True, skip sparse regions and read only actual data (recommended)
                        If False, fill sparse regions with zeros (memory warning)

        Note:
            USN Journal $J stream is typically a sparse file.
            Logical size can be tens of GB but actual data is only a portion.
            Recommended to use skip_sparse=True to read only actual data.
        """
        if self._dissect_fs is not None:
            raise FilesystemError("$UsnJrnl is an NTFS-specific structure (current filesystem: "
                                  f"{self._dissect_fs_type})")
        # $Extend directory (usually entry 11)
        extend_inode = 11

        # Find $UsnJrnl under $Extend
        usnjrnl_inode = self._find_in_directory(extend_inode, '$UsnJrnl')
        if usnjrnl_inode is None:
            raise FilesystemError("$UsnJrnl not found")

        if skip_sparse:
            # [2026-01] Skip sparse regions and read only actual data
            return self._read_file_skip_sparse(usnjrnl_inode, stream_name='$J', max_size=max_size)
        else:
            # Legacy method: fill sparse regions with zeros
            return self.read_file_by_inode(usnjrnl_inode, stream_name='$J', max_size=max_size)

    def _read_file_skip_sparse(
        self,
        inode: int,
        stream_name: str = None,
        max_size: int = None
    ) -> bytes:
        """
        [2026-01] Skip sparse regions and read only actual data

        Useful for large sparse files like USN Journal.
        Does not include zeros from sparse regions, significantly reducing file size.
        """
        if self._extractor is None:
            raise FilesystemError("No partition selected or unsupported filesystem")

        # Read MFT entry
        entry = self._extractor.read_mft_entry(inode)
        if entry[:4] != b'FILE':
            raise FilesystemError(f"Invalid MFT entry at inode {inode}")

        # Extract metadata and data runs
        metadata = self._extractor._parse_mft_entry_metadata(entry, inode, stream_name)

        # Resident data
        if metadata.is_resident:
            data = metadata.resident_data
            if max_size:
                data = data[:max_size]
            return data

        # Non-resident: skip sparse regions and read only actual data
        data = bytearray()
        bytes_read = 0
        target_size = max_size if max_size else metadata.size

        # Limit to 1GB max (USN Journal actual data is typically hundreds of MB)
        MAX_USNJRNL_SIZE = 1 * 1024 * 1024 * 1024
        if target_size > MAX_USNJRNL_SIZE:
            target_size = MAX_USNJRNL_SIZE
            logger.info(f"Limiting USN Journal read to {MAX_USNJRNL_SIZE // (1024*1024)}MB")

        for run in metadata.data_runs:
            if bytes_read >= target_size:
                break

            if run.is_sparse:
                # Skip sparse regions (do not fill with zeros)
                continue

            # Read actual clusters
            run_offset = self._extractor.partition_offset + (run.lcn * self._extractor.cluster_size)
            run_size = min(run.length * self._extractor.cluster_size, target_size - bytes_read)

            chunk = self._backend.read(run_offset, run_size)
            data.extend(chunk)
            bytes_read += len(chunk)

        logger.info(f"USN Journal: read {len(data)} bytes (skipped sparse regions)")
        return bytes(data)

    # ==========================================================================
    # Disk Info
    # ==========================================================================

    def get_disk_info(self) -> DiskInfo:
        """Return disk information"""
        return self._backend.get_disk_info()

    def get_partition_table_type(self) -> str:
        """Return partition table type (MBR/GPT)"""
        return self._partition_table_type

    # ==========================================================================
    # Context Manager
    # ==========================================================================

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self):
        """Release resources"""
        # Release dissect handles
        if self._dissect_fs is not None:
            try:
                if hasattr(self._dissect_fs, 'close'):
                    self._dissect_fs.close()
            except Exception:
                pass
            self._dissect_fs = None
        if self._dissect_fh is not None:
            try:
                self._dissect_fh.close()
            except Exception:
                pass
            self._dissect_fh = None
        self._dissect_fs_type = None

        if self._backend:
            self._backend.close()
        self._extractor = None
        self._path_cache.clear()


# ==============================================================================
# Convenience Functions
# ==============================================================================

def read_locked_file(path: str, drive_number: int = 0) -> bytes:
    """
    Read locked file (convenience function)

    Reads files locked by Windows (registry, pagefile, etc.) via raw disk access.

    Args:
        path: File path (e.g., "C:/Windows/System32/config/SYSTEM")
        drive_number: Drive number (default 0)

    Returns:
        File content

    Usage:
        system_hive = read_locked_file("C:/Windows/System32/config/SYSTEM")
    """
    with ForensicDiskAccessor.from_physical_disk(drive_number) as disk:
        # Infer partition selection from drive letter
        partition_index = 0  # Default to first partition

        # Extract drive letter from path
        if len(path) > 2 and path[1] == ':':
            drive_letter = path[0].upper()
            # C: = partition 0 (simple mapping, actually more complex)
            partition_index = ord(drive_letter) - ord('C')
            partition_index = max(0, partition_index)

        partitions = disk.list_partitions()
        if partition_index >= len(partitions):
            partition_index = 0

        disk.select_partition(partition_index)
        return disk.read_file(path)


def stream_large_file(path: str, drive_number: int = 0, chunk_size: int = 64 * 1024 * 1024):
    """
    Stream large file (convenience function)

    Memory-efficiently streams large files like pagefile.sys, hiberfil.sys.

    Args:
        path: File path
        drive_number: Drive number
        chunk_size: Chunk size (default 64MB)

    Yields:
        File data chunks
    """
    with ForensicDiskAccessor.from_physical_disk(drive_number) as disk:
        partition_index = 0
        if len(path) > 2 and path[1] == ':':
            drive_letter = path[0].upper()
            partition_index = ord(drive_letter) - ord('C')
            partition_index = max(0, partition_index)

        partitions = disk.list_partitions()
        if partition_index >= len(partitions):
            partition_index = 0

        disk.select_partition(partition_index)
        yield from disk.stream_file(path, chunk_size)
