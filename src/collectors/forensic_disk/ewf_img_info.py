# -*- coding: utf-8 -*-
"""
EwfImgInfo - pyewf to pytsk3 bridge class

Wraps a pyewf handle with the pytsk3.Img_Info interface,
allowing pytsk3 to directly parse filesystems within E01 images.

This enables reading all filesystems (ext4, HFS+, APFS, etc.) via pytsk3.

Usage:
    from forensic_disk.ewf_img_info import open_e01_as_pytsk3
    import pytsk3

    # Open E01 image
    img_info = open_e01_as_pytsk3(['evidence.E01'])

    # Parse filesystem with pytsk3
    fs_info = pytsk3.FS_Info(img_info, offset=partition_offset)

    # Read files (supports all filesystems: ext4, HFS+, APFS, etc.)
    file_entry = fs_info.open('/etc/passwd')
    content = file_entry.read_random(0, file_entry.info.meta.size)
"""

import logging
from typing import List, Optional, Union
from pathlib import Path

logger = logging.getLogger(__name__)

# Check pyewf availability
try:
    import pyewf
    PYEWF_AVAILABLE = True
except ImportError:
    PYEWF_AVAILABLE = False
    logger.warning("pyewf not available - E01 image support disabled")

# Check pytsk3 availability
try:
    import pytsk3
    PYTSK3_AVAILABLE = True
except ImportError:
    PYTSK3_AVAILABLE = False
    logger.warning("pytsk3 not available - filesystem parsing disabled")


class EwfImgInfo(pytsk3.Img_Info if PYTSK3_AVAILABLE else object):
    """
    Wraps a pyewf handle as pytsk3.Img_Info

    Overrides the read and get_size methods of pytsk3.Img_Info
    to read E01 image data through the pyewf handle.
    """

    def __init__(self, ewf_handle: 'pyewf.handle'):
        """
        Args:
            ewf_handle: pyewf.handle instance (already opened)
        """
        if not PYTSK3_AVAILABLE:
            raise ImportError("pytsk3 is required for EwfImgInfo")

        self._ewf_handle = ewf_handle
        self._size = ewf_handle.get_media_size()

        # Initialize pytsk3.Img_Info - use external image type with url=""
        # Since TSK_IMG_TYPE_EXTERNAL is not directly supported by pytsk3,
        # skip URL-based initialization and use pure Python interface
        super(EwfImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        """Release resources"""
        if self._ewf_handle:
            try:
                self._ewf_handle.close()
            except Exception as e:
                logger.debug(f"Error closing ewf handle: {e}")
            self._ewf_handle = None

    def read(self, offset: int, size: int) -> bytes:
        """
        Read data from E01 image

        Args:
            offset: Starting offset (bytes)
            size: Number of bytes to read

        Returns:
            Data read from image
        """
        if not self._ewf_handle:
            raise IOError("EWF handle is closed")

        try:
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)
        except Exception as e:
            logger.error(f"Error reading from E01 at offset {offset}: {e}")
            raise

    def get_size(self) -> int:
        """
        Return total size of E01 image

        Returns:
            Media size (bytes)
        """
        return self._size

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class BackendImgInfo(pytsk3.Img_Info if PYTSK3_AVAILABLE else object):
    """
    Bridge any UnifiedDiskReader backend to pytsk3.Img_Info

    Allows pytsk3 to parse filesystems on any disk source (physical disk,
    E01, RAW, etc.) by wrapping the UnifiedDiskReader.read()/get_size()
    interface.  This is the key bridge that enables pytsk3-based file
    extraction for non-NTFS filesystems (FAT32, exFAT, ext2/3/4, HFS+,
    ISO9660, UFS) regardless of the underlying image format.

    Usage:
        from forensic_disk.ewf_img_info import BackendImgInfo
        import pytsk3

        img_info = BackendImgInfo(backend)
        fs_info = pytsk3.FS_Info(img_info, offset=partition_offset)
    """

    # LRU block cache: reduces random I/O through virtual disk translation layers
    # (VDI/VMDK/VHD). pytsk3 makes many small reads (4KB inode, 1KB superblock) that
    # would each require VDI block mapping. Caching 1MB blocks (64 blocks = 64MB max)
    # dramatically reduces actual disk I/O.
    _CACHE_BLOCK_SIZE = 1024 * 1024  # 1MB per cache block
    _CACHE_MAX_BLOCKS = 256          # 256MB max cache (prevents USB I/O saturation on large VDI/VMDK)

    def __init__(self, backend):
        """
        Args:
            backend: Any object implementing read(offset, size) -> bytes
                     and get_size() -> int  (e.g. UnifiedDiskReader subclass)
        """
        if not PYTSK3_AVAILABLE:
            raise ImportError("pytsk3 is required for BackendImgInfo")

        self._backend = backend
        self._cache = {}        # block_index -> bytes
        self._cache_order = []  # LRU order (oldest first)
        super(BackendImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        """Release cache memory. Backend lifecycle managed by caller."""
        self._cache.clear()
        self._cache_order.clear()

    def _read_cached_block(self, block_idx: int) -> bytes:
        """Read a 1MB block, using cache if available."""
        if block_idx in self._cache:
            # Move to end (most recently used)
            try:
                self._cache_order.remove(block_idx)
            except ValueError:
                pass
            self._cache_order.append(block_idx)
            return self._cache[block_idx]

        # Read from backend
        offset = block_idx * self._CACHE_BLOCK_SIZE
        disk_size = self._backend.get_size()
        read_size = min(self._CACHE_BLOCK_SIZE, disk_size - offset)
        if read_size <= 0:
            return b''

        data = self._backend.read(offset, read_size)

        # Evict oldest if cache full
        while len(self._cache) >= self._CACHE_MAX_BLOCKS:
            oldest = self._cache_order.pop(0)
            self._cache.pop(oldest, None)

        self._cache[block_idx] = data
        self._cache_order.append(block_idx)
        return data

    def read(self, offset: int, size: int) -> bytes:
        """
        Read data via the backend with 1MB block caching.
        Small reads (typical from pytsk3) are served from cache when possible.
        """
        # For very large reads (>4MB), bypass cache to avoid thrashing
        if size > 4 * self._CACHE_BLOCK_SIZE:
            return self._backend.read(offset, size)

        result = bytearray()
        remaining = size
        pos = offset

        while remaining > 0:
            block_idx = pos // self._CACHE_BLOCK_SIZE
            block_offset = pos % self._CACHE_BLOCK_SIZE
            block_data = self._read_cached_block(block_idx)

            if not block_data:
                break

            available = len(block_data) - block_offset
            chunk_size = min(remaining, available)
            result.extend(block_data[block_offset:block_offset + chunk_size])
            pos += chunk_size
            remaining -= chunk_size

        return bytes(result)

    def get_size(self) -> int:
        """Return total image/disk size via the backend"""
        return self._backend.get_size()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


class RawImgInfo(pytsk3.Img_Info if PYTSK3_AVAILABLE else object):
    """
    Wraps RAW/DD image as pytsk3.Img_Info

    Wraps RAW image files for use with pytsk3.
    """

    def __init__(self, raw_path: str):
        """
        Args:
            raw_path: RAW image file path
        """
        if not PYTSK3_AVAILABLE:
            raise ImportError("pytsk3 is required for RawImgInfo")

        self._file = open(raw_path, 'rb')
        self._file.seek(0, 2)  # Move to end
        self._size = self._file.tell()
        self._file.seek(0)  # Return to start

        super(RawImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        """Release resources"""
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None

    def read(self, offset: int, size: int) -> bytes:
        """Read data from RAW image"""
        if not self._file:
            raise IOError("File handle is closed")

        self._file.seek(offset)
        return self._file.read(size)

    def get_size(self) -> int:
        """Return image size"""
        return self._size

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def open_e01_as_pytsk3(e01_paths: Union[str, List[str]]) -> EwfImgInfo:
    """
    Open E01 file as pytsk3.Img_Info

    Args:
        e01_paths: E01 file path or list of paths (supports split images)
                   e.g.: 'evidence.E01' or ['evidence.E01', 'evidence.E02']

    Returns:
        EwfImgInfo: pytsk3.Img_Info compatible object

    Raises:
        ImportError: pyewf or pytsk3 not installed
        FileNotFoundError: E01 file not found
        IOError: Failed to open E01 file
    """
    if not PYEWF_AVAILABLE:
        raise ImportError("pyewf is required to open E01 images. Install with: pip install pyewf-python")

    if not PYTSK3_AVAILABLE:
        raise ImportError("pytsk3 is required for filesystem parsing. Install with: pip install pytsk3")

    # Convert single path to list
    if isinstance(e01_paths, str):
        e01_paths = [e01_paths]

    # Check file existence
    for path in e01_paths:
        if not Path(path).exists():
            raise FileNotFoundError(f"E01 file not found: {path}")

    # Open E01 image with pyewf
    try:
        # Auto-detect split segments with pyewf.glob()
        if len(e01_paths) == 1:
            all_segments = pyewf.glob(e01_paths[0])
        else:
            all_segments = e01_paths

        ewf_handle = pyewf.handle()
        ewf_handle.open(all_segments)

        logger.info(f"Opened E01 image: {e01_paths[0]} ({len(all_segments)} segment(s))")
        logger.info(f"Media size: {ewf_handle.get_media_size() / (1024**3):.2f} GB")

        return EwfImgInfo(ewf_handle)

    except Exception as e:
        logger.error(f"Failed to open E01 image: {e}")
        raise IOError(f"Failed to open E01 image: {e}")


def open_raw_as_pytsk3(raw_path: str) -> RawImgInfo:
    """
    Open RAW/DD image file as pytsk3.Img_Info

    Args:
        raw_path: RAW image file path

    Returns:
        RawImgInfo: pytsk3.Img_Info compatible object
    """
    if not PYTSK3_AVAILABLE:
        raise ImportError("pytsk3 is required for filesystem parsing")

    if not Path(raw_path).exists():
        raise FileNotFoundError(f"RAW file not found: {raw_path}")

    return RawImgInfo(raw_path)


def detect_filesystem_type(img_info: 'pytsk3.Img_Info', offset: int = 0) -> str:
    """
    Detect filesystem type using pytsk3

    Args:
        img_info: pytsk3.Img_Info instance
        offset: Partition offset (bytes)

    Returns:
        Filesystem type string ('NTFS', 'ext4', 'HFS+', 'APFS', 'Unknown')
    """
    if not PYTSK3_AVAILABLE:
        return 'Unknown'

    try:
        fs_info = pytsk3.FS_Info(img_info, offset=offset)
        fs_type = fs_info.info.ftype

        # pytsk3 filesystem type constant mapping
        type_map = {
            pytsk3.TSK_FS_TYPE_NTFS: 'NTFS',
            pytsk3.TSK_FS_TYPE_FAT12: 'FAT12',
            pytsk3.TSK_FS_TYPE_FAT16: 'FAT16',
            pytsk3.TSK_FS_TYPE_FAT32: 'FAT32',
            pytsk3.TSK_FS_TYPE_EXFAT: 'exFAT',
            pytsk3.TSK_FS_TYPE_EXT2: 'ext2',
            pytsk3.TSK_FS_TYPE_EXT3: 'ext3',
            pytsk3.TSK_FS_TYPE_EXT4: 'ext4',
            pytsk3.TSK_FS_TYPE_HFS: 'HFS',
            pytsk3.TSK_FS_TYPE_HFS_DETECT: 'HFS+',
        }

        # APFS is supported in TSK 4.12+
        if hasattr(pytsk3, 'TSK_FS_TYPE_APFS'):
            type_map[pytsk3.TSK_FS_TYPE_APFS] = 'APFS'

        return type_map.get(fs_type, 'Unknown')

    except Exception as e:
        logger.debug(f"Filesystem detection failed at offset {offset}: {e}")
        return 'Unknown'


def detect_partitions_pytsk3(img_info: 'pytsk3.Img_Info') -> List[dict]:
    """
    Detect partition list using pytsk3

    Args:
        img_info: pytsk3.Img_Info instance

    Returns:
        List of partition info dictionaries
        [{'index': 0, 'offset': 0, 'size': ..., 'filesystem': 'NTFS'}, ...]
    """
    if not PYTSK3_AVAILABLE:
        return []

    partitions = []

    try:
        vol_info = pytsk3.Volume_Info(img_info)

        for part in vol_info:
            # Skip meta/extended partitions
            if part.desc.decode('utf-8', errors='ignore').lower() in ('meta', 'extended'):
                continue

            # Skip empty partitions
            if part.len == 0:
                continue

            offset = part.start * vol_info.info.block_size
            size = part.len * vol_info.info.block_size
            fs_type = detect_filesystem_type(img_info, offset)

            partitions.append({
                'index': len(partitions),
                'offset': offset,
                'size': size,
                'filesystem': fs_type,
                'description': part.desc.decode('utf-8', errors='ignore')
            })

    except Exception as e:
        logger.debug(f"Partition detection failed: {e}")

        # If no partition table (volume image)
        # Detect filesystem directly at offset 0
        fs_type = detect_filesystem_type(img_info, 0)
        if fs_type != 'Unknown':
            partitions.append({
                'index': 0,
                'offset': 0,
                'size': img_info.get_size(),
                'filesystem': fs_type,
                'description': 'Volume Image'
            })

    return partitions


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
