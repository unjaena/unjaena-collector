# -*- coding: utf-8 -*-
"""
Disk Backends - UnifiedDiskReader implementations

Concrete implementations for disk sources:
1. PhysicalDiskBackend - Windows physical disk (\\\\.\\PhysicalDrive{N})
2. E01DiskBackend - E01/EWF forensic image (pyewf)
3. RAWImageBackend - RAW/DD image file
4. VMDKDiskBackend - VMware VMDK
5. VHDDiskBackend - Hyper-V VHD
6. VHDXDiskBackend - Hyper-V VHDX
7. QCOW2DiskBackend - KVM/QEMU QCOW2
8. VDIDiskBackend - VirtualBox VDI
9. DMGDiskBackend - Apple DMG (UDIF) — cross-platform, pure Python

Usage:
    # Physical disk
    with PhysicalDiskBackend(0) as disk:
        mbr = disk.read(0, 512)

    # E01 image
    with E01DiskBackend("evidence.E01") as disk:
        mbr = disk.read(0, 512)

    # RAW image
    with RAWImageBackend("disk.dd") as disk:
        mbr = disk.read(0, 512)

    # DMG image
    with DMGDiskBackend("macos.dmg") as disk:
        mbr = disk.read(0, 512)
"""

import os
import sys
import struct
import logging
import zlib
import bz2
import base64
import plistlib
import bisect
from collections import OrderedDict
from pathlib import Path
from typing import Optional, List, Dict, Tuple, NamedTuple

from .unified_disk_reader import (
    UnifiedDiskReader,
    DiskInfo,
    DiskSourceType,
    DiskError,
    DiskNotFoundError,
    DiskPermissionError,
    DiskReadError
)

logger = logging.getLogger(__name__)

# Debug output control
_DEBUG_OUTPUT = False
def _debug_print(msg):
    if _DEBUG_OUTPUT: print(f"[DiskBackend] {msg}")


# ==============================================================================
# Physical Disk Backend (Windows)
# ==============================================================================

class PhysicalDiskBackend(UnifiedDiskReader):
    """
    Windows physical disk backend

    Directly accesses raw sectors through \\\\.\\PhysicalDrive{N}.
    Requires administrator privileges.

    Features:
    - Raw sector reading (MBR, VBR, MFT, etc.)
    - Bypass file locks (pagefile.sys, registry, etc.)
    - Automatic sector alignment handling

    Usage:
        with PhysicalDiskBackend(0) as disk:  # PhysicalDrive0
            mbr = disk.read(0, 512)
            vbr = disk.read(2048 * 512, 512)  # First partition VBR
    """

    def __init__(self, drive_number: int = 0):
        """
        Args:
            drive_number: Physical drive number (0 = PhysicalDrive0)
        """
        super().__init__()

        if sys.platform != 'win32':
            raise DiskError("PhysicalDiskBackend is Windows-only")

        self.drive_number = drive_number
        self.drive_path = f"\\\\.\\PhysicalDrive{drive_number}"
        self._handle = None

        self._open()

    def _open(self):
        """Open physical drive"""
        try:
            import win32file
            import win32con
            import pywintypes

            logger.info(f"Opening physical disk: {self.drive_path}")

            # Open physical drive (read-only)
            self._handle = win32file.CreateFile(
                self.drive_path,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                0,
                None
            )

            # Get disk geometry
            self._get_disk_geometry()

            self._is_open = True
            logger.info(f"Physical disk opened successfully: {self._disk_size / (1024**3):.2f} GB")

        except ImportError:
            raise DiskError("pywin32 not installed. Run: pip install pywin32")
        except pywintypes.error as e:
            error_code = e.winerror if hasattr(e, 'winerror') else e.args[0]
            if error_code == 5:  # ERROR_ACCESS_DENIED
                raise DiskPermissionError(
                    f"Access denied to {self.drive_path}. "
                    "Run as Administrator."
                )
            elif error_code == 2:  # ERROR_FILE_NOT_FOUND
                raise DiskNotFoundError(f"Disk not found: {self.drive_path}")
            else:
                raise DiskError(f"Failed to open {self.drive_path}: {e}")

    def _get_disk_geometry(self):
        """Get disk geometry and size"""
        try:
            import win32file
            import winioctlcon

            # IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
            geometry = win32file.DeviceIoControl(
                self._handle,
                winioctlcon.IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None,
                256
            )

            # Parse DISK_GEOMETRY_EX structure
            # Offset 0-24: DISK_GEOMETRY
            # Offset 24-32: DiskSize (LARGE_INTEGER)
            if len(geometry) >= 32:
                self._disk_size = struct.unpack('<Q', geometry[24:32])[0]

            # Sector size (offset 20-24 in DISK_GEOMETRY)
            if len(geometry) >= 24:
                self._sector_size = struct.unpack('<I', geometry[20:24])[0]
                if self._sector_size == 0:
                    self._sector_size = 512

        except Exception as e:
            logger.warning(f"Could not get disk geometry: {e}")
            self._sector_size = 512
            self._disk_size = 0

    def read(self, offset: int, size: int) -> bytes:
        """Read raw bytes"""
        if not self._is_open or not self._handle:
            raise DiskError("Disk not open")

        try:
            import win32file

            # Sector alignment
            aligned_offset = (offset // self._sector_size) * self._sector_size
            offset_in_sector = offset - aligned_offset
            aligned_size = ((offset_in_sector + size + self._sector_size - 1) //
                           self._sector_size) * self._sector_size

            # Seek
            win32file.SetFilePointer(self._handle, aligned_offset, win32file.FILE_BEGIN)

            # Read
            _, data = win32file.ReadFile(self._handle, aligned_size)

            # Extract requested range
            result = bytes(data[offset_in_sector:offset_in_sector + size])
            return result

        except Exception as e:
            raise DiskReadError(f"Read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        """Return disk metadata"""
        return DiskInfo(
            source_type=DiskSourceType.PHYSICAL_DISK,
            total_size=self._disk_size,
            sector_size=self._sector_size,
            source_path=self.drive_path,
            is_readonly=True
        )

    def get_size(self) -> int:
        """Get total disk size"""
        return self._disk_size

    def close(self):
        """Release resources"""
        if self._handle:
            try:
                import win32file
                win32file.CloseHandle(self._handle)
                logger.debug(f"Closed physical disk: {self.drive_path}")
            except Exception as e:
                logger.warning(f"Error closing disk: {e}")
            finally:
                self._handle = None
                self._is_open = False


# ==============================================================================
# E01 Disk Backend (pyewf)
# ==============================================================================

class E01DiskBackend(UnifiedDiskReader):
    """
    E01/EWF forensic image backend

    Uses pyewf library to access E01 images.
    Transparently handles compressed/split E01 files.

    Features:
    - E01, Ex01 multi-segment support
    - Automatic decompression of compressed images
    - Raw sector access

    Usage:
        with E01DiskBackend("evidence.E01") as disk:
            mbr = disk.read(0, 512)
    """

    def __init__(self, e01_path: str):
        """
        Args:
            e01_path: Path to first E01 segment file
        """
        super().__init__()

        self.e01_path = e01_path
        self._ewf_handle = None

        self._open()

    def _open(self):
        """Open E01 image"""
        try:
            import pyewf

            # Find all segment files
            segments = self._find_segments(self.e01_path)
            if not segments:
                raise DiskNotFoundError(f"E01 file not found: {self.e01_path}")

            logger.info(f"Opening E01 image: {self.e01_path} ({len(segments)} segments)")

            # Open pyewf handle
            self._ewf_handle = pyewf.handle()
            self._ewf_handle.open(segments)

            # Get metadata
            self._disk_size = self._ewf_handle.get_media_size()
            self._sector_size = 512  # EWF typically uses 512-byte sectors

            self._is_open = True
            logger.info(f"E01 image opened: {self._disk_size / (1024**3):.2f} GB")

        except ImportError:
            raise DiskError("pyewf not installed. Run: pip install libewf-python")
        except Exception as e:
            raise DiskError(f"Failed to open E01: {e}")

    def _find_segments(self, e01_path: str) -> List[str]:
        """
        Find E01 segment files

        E01, E02, E03... or Ex01, Ex02... patterns
        """
        import glob

        e01_path = str(e01_path)
        path = Path(e01_path)

        if not path.exists():
            return []

        # Analyze extension pattern
        ext = path.suffix.lower()
        base = str(path.with_suffix(''))

        if ext.startswith('.e') and len(ext) == 4:
            # .E01 pattern
            pattern = f"{base}.[Ee]*"
        elif ext.startswith('.ex') or ext.startswith('.Ex'):
            # .Ex01 pattern
            pattern = f"{base}.[Ee][Xx]*"
        else:
            # Single file
            return [e01_path]

        segments = sorted(glob.glob(pattern))
        return segments if segments else [e01_path]

    def read(self, offset: int, size: int) -> bytes:
        """Read raw bytes"""
        if not self._is_open or not self._ewf_handle:
            raise DiskError("E01 image not open")

        try:
            self._ewf_handle.seek(offset)
            data = self._ewf_handle.read(size)
            return data
        except Exception as e:
            raise DiskReadError(f"E01 read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        """Return disk metadata"""
        info = DiskInfo(
            source_type=DiskSourceType.E01_IMAGE,
            total_size=self._disk_size,
            sector_size=self._sector_size,
            source_path=self.e01_path,
            is_readonly=True
        )

        # Add EWF metadata
        if self._ewf_handle:
            try:
                # Get additional metadata if available
                pass  # Depends on pyewf version
            except Exception:
                pass

        return info

    def get_size(self) -> int:
        """Get total disk size"""
        return self._disk_size

    def close(self):
        """Release resources"""
        if self._ewf_handle:
            try:
                self._ewf_handle.close()
                logger.debug(f"Closed E01 image: {self.e01_path}")
            except Exception as e:
                logger.warning(f"Error closing E01: {e}")
            finally:
                self._ewf_handle = None
                self._is_open = False


# ==============================================================================
# Virtual Disk Backends (dissect.hypervisor)
# ==============================================================================

class VMDKDiskBackend(UnifiedDiskReader):
    """VMware VMDK virtual disk backend"""

    def __init__(self, vmdk_path: str):
        super().__init__()
        self.image_path = vmdk_path
        self._fh = None
        self._vmdk = None
        self._open()

    def _open(self):
        if not os.path.exists(self.image_path):
            raise DiskNotFoundError(f"VMDK file not found: {self.image_path}")
        try:
            from dissect.hypervisor.disk.vmdk import VMDK
            logger.info(f"Opening VMDK image: {self.image_path}")
            self._fh = open(self.image_path, 'rb')
            self._vmdk = VMDK(self._fh).open()
            self._disk_size = self._vmdk.size
            self._sector_size = 512
            self._is_open = True
            logger.info(f"VMDK image opened: {self._disk_size / (1024**3):.2f} GB")
        except ImportError:
            raise DiskError("dissect.hypervisor not installed. Run: pip install dissect.hypervisor")
        except Exception as e:
            raise DiskError(f"Failed to open VMDK: {e}")

    _MAX_READ_CHUNK = 1024 * 1024  # 1MB

    def read(self, offset: int, size: int) -> bytes:
        if not self._is_open:
            raise DiskError("VMDK not open")
        try:
            if size <= self._MAX_READ_CHUNK:
                self._vmdk.seek(offset)
                return self._vmdk.read(size)
            else:
                result = bytearray()
                pos = offset
                remaining = size
                while remaining > 0:
                    chunk = min(remaining, self._MAX_READ_CHUNK)
                    self._vmdk.seek(pos)
                    result.extend(self._vmdk.read(chunk))
                    pos += chunk
                    remaining -= chunk
                return bytes(result)
        except Exception as e:
            raise DiskReadError(f"VMDK read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        return DiskInfo(source_type=DiskSourceType.VMDK_IMAGE, total_size=self._disk_size,
                        sector_size=self._sector_size, source_path=self.image_path, is_readonly=True)

    def get_size(self) -> int:
        return self._disk_size

    def close(self):
        if self._vmdk and hasattr(self._vmdk, 'close'):
            try: self._vmdk.close()
            except Exception: pass
        self._vmdk = None
        if self._fh:
            try: self._fh.close()
            except Exception: pass
            self._fh = None
        self._is_open = False


class VHDDiskBackend(UnifiedDiskReader):
    """Hyper-V VHD virtual disk backend"""

    def __init__(self, vhd_path: str):
        super().__init__()
        self.image_path = vhd_path
        self._fh = None
        self._vhd = None
        self._open()

    def _open(self):
        if not os.path.exists(self.image_path):
            raise DiskNotFoundError(f"VHD file not found: {self.image_path}")
        try:
            from dissect.hypervisor.disk.vhd import VHD
            logger.info(f"Opening VHD image: {self.image_path}")
            self._fh = open(self.image_path, 'rb')
            self._vhd = VHD(self._fh).open()
            self._disk_size = self._vhd.size
            self._sector_size = 512
            self._is_open = True
            logger.info(f"VHD image opened: {self._disk_size / (1024**3):.2f} GB")
        except ImportError:
            raise DiskError("dissect.hypervisor not installed. Run: pip install dissect.hypervisor")
        except Exception as e:
            raise DiskError(f"Failed to open VHD: {e}")

    _MAX_READ_CHUNK = 1024 * 1024  # 1MB

    def read(self, offset: int, size: int) -> bytes:
        if not self._is_open:
            raise DiskError("VHD not open")
        try:
            if size <= self._MAX_READ_CHUNK:
                self._vhd.seek(offset)
                return self._vhd.read(size)
            else:
                result = bytearray()
                pos = offset
                remaining = size
                while remaining > 0:
                    chunk = min(remaining, self._MAX_READ_CHUNK)
                    self._vhd.seek(pos)
                    result.extend(self._vhd.read(chunk))
                    pos += chunk
                    remaining -= chunk
                return bytes(result)
        except Exception as e:
            raise DiskReadError(f"VHD read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        return DiskInfo(source_type=DiskSourceType.VHD_IMAGE, total_size=self._disk_size,
                        sector_size=self._sector_size, source_path=self.image_path, is_readonly=True)

    def get_size(self) -> int:
        return self._disk_size

    def close(self):
        if self._vhd and hasattr(self._vhd, 'close'):
            try: self._vhd.close()
            except Exception: pass
        self._vhd = None
        if self._fh:
            try: self._fh.close()
            except Exception: pass
            self._fh = None
        self._is_open = False


class VHDXDiskBackend(UnifiedDiskReader):
    """Hyper-V VHDX virtual disk backend"""

    def __init__(self, vhdx_path: str):
        super().__init__()
        self.image_path = vhdx_path
        self._fh = None
        self._vhdx = None
        self._open()

    def _open(self):
        if not os.path.exists(self.image_path):
            raise DiskNotFoundError(f"VHDX file not found: {self.image_path}")
        try:
            from dissect.hypervisor.disk.vhdx import VHDX
            logger.info(f"Opening VHDX image: {self.image_path}")
            self._fh = open(self.image_path, 'rb')
            self._vhdx = VHDX(self._fh).open()
            self._disk_size = self._vhdx.size
            self._sector_size = 512
            self._is_open = True
            logger.info(f"VHDX image opened: {self._disk_size / (1024**3):.2f} GB")
        except ImportError:
            raise DiskError("dissect.hypervisor not installed. Run: pip install dissect.hypervisor")
        except Exception as e:
            raise DiskError(f"Failed to open VHDX: {e}")

    _MAX_READ_CHUNK = 1024 * 1024  # 1MB

    def read(self, offset: int, size: int) -> bytes:
        if not self._is_open:
            raise DiskError("VHDX not open")
        try:
            if size <= self._MAX_READ_CHUNK:
                self._vhdx.seek(offset)
                return self._vhdx.read(size)
            else:
                result = bytearray()
                pos = offset
                remaining = size
                while remaining > 0:
                    chunk = min(remaining, self._MAX_READ_CHUNK)
                    self._vhdx.seek(pos)
                    result.extend(self._vhdx.read(chunk))
                    pos += chunk
                    remaining -= chunk
                return bytes(result)
        except Exception as e:
            raise DiskReadError(f"VHDX read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        return DiskInfo(source_type=DiskSourceType.VHDX_IMAGE, total_size=self._disk_size,
                        sector_size=self._sector_size, source_path=self.image_path, is_readonly=True)

    def get_size(self) -> int:
        return self._disk_size

    def close(self):
        if self._vhdx and hasattr(self._vhdx, 'close'):
            try: self._vhdx.close()
            except Exception: pass
        self._vhdx = None
        if self._fh:
            try: self._fh.close()
            except Exception: pass
            self._fh = None
        self._is_open = False


class QCOW2DiskBackend(UnifiedDiskReader):
    """KVM/QEMU QCOW2 virtual disk backend"""

    def __init__(self, qcow2_path: str):
        super().__init__()
        self.image_path = qcow2_path
        self._fh = None
        self._qcow2 = None
        self._open()

    def _open(self):
        if not os.path.exists(self.image_path):
            raise DiskNotFoundError(f"QCOW2 file not found: {self.image_path}")
        try:
            from dissect.hypervisor.disk.qcow2 import QCow2
            logger.info(f"Opening QCOW2 image: {self.image_path}")
            self._fh = open(self.image_path, 'rb')
            self._qcow2 = QCow2(self._fh).open()
            self._disk_size = self._qcow2.size
            self._sector_size = 512
            self._is_open = True
            logger.info(f"QCOW2 image opened: {self._disk_size / (1024**3):.2f} GB")
        except ImportError:
            raise DiskError("dissect.hypervisor not installed. Run: pip install dissect.hypervisor")
        except Exception as e:
            raise DiskError(f"Failed to open QCOW2: {e}")

    _MAX_READ_CHUNK = 1024 * 1024  # 1MB

    def read(self, offset: int, size: int) -> bytes:
        if not self._is_open:
            raise DiskError("QCOW2 not open")
        try:
            if size <= self._MAX_READ_CHUNK:
                self._qcow2.seek(offset)
                return self._qcow2.read(size)
            else:
                result = bytearray()
                pos = offset
                remaining = size
                while remaining > 0:
                    chunk = min(remaining, self._MAX_READ_CHUNK)
                    self._qcow2.seek(pos)
                    result.extend(self._qcow2.read(chunk))
                    pos += chunk
                    remaining -= chunk
                return bytes(result)
        except Exception as e:
            raise DiskReadError(f"QCOW2 read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        return DiskInfo(source_type=DiskSourceType.QCOW2_IMAGE, total_size=self._disk_size,
                        sector_size=self._sector_size, source_path=self.image_path, is_readonly=True)

    def get_size(self) -> int:
        return self._disk_size

    def close(self):
        if self._qcow2 and hasattr(self._qcow2, 'close'):
            try: self._qcow2.close()
            except Exception: pass
        self._qcow2 = None
        if self._fh:
            try: self._fh.close()
            except Exception: pass
            self._fh = None
        self._is_open = False


class VDIDiskBackend(UnifiedDiskReader):
    """VirtualBox VDI virtual disk backend"""

    def __init__(self, vdi_path: str):
        super().__init__()
        self.image_path = vdi_path
        self._fh = None
        self._vdi = None
        self._open()

    def _open(self):
        if not os.path.exists(self.image_path):
            raise DiskNotFoundError(f"VDI file not found: {self.image_path}")
        try:
            from dissect.hypervisor.disk.vdi import VDI
            logger.info(f"Opening VDI image: {self.image_path}")
            self._fh = open(self.image_path, 'rb')
            self._vdi = VDI(self._fh).open()
            self._disk_size = self._vdi.size
            self._sector_size = 512
            self._is_open = True
            logger.info(f"VDI image opened: {self._disk_size / (1024**3):.2f} GB")
        except ImportError:
            raise DiskError("dissect.hypervisor not installed. Run: pip install dissect.hypervisor")
        except Exception as e:
            raise DiskError(f"Failed to open VDI: {e}")

    # Max single read size to prevent dissect VDIStream._read() bug from
    # allocating huge zero buffers (e.g. 60GB for readall on unallocated blocks).
    _MAX_READ_CHUNK = 1024 * 1024  # 1MB

    def read(self, offset: int, size: int) -> bytes:
        if not self._is_open:
            raise DiskError("VDI not open")
        try:
            # Guard against dissect VDIStream._read() bug: reads spanning multiple
            # blocks may allocate b"\x00" * size for unallocated regions.
            # Chunk large reads to prevent multi-GB memory allocation.
            if size <= self._MAX_READ_CHUNK:
                self._vdi.seek(offset)
                return self._vdi.read(size)
            else:
                result = bytearray()
                pos = offset
                remaining = size
                while remaining > 0:
                    chunk = min(remaining, self._MAX_READ_CHUNK)
                    self._vdi.seek(pos)
                    result.extend(self._vdi.read(chunk))
                    pos += chunk
                    remaining -= chunk
                return bytes(result)
        except Exception as e:
            raise DiskReadError(f"VDI read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        return DiskInfo(source_type=DiskSourceType.VDI_IMAGE, total_size=self._disk_size,
                        sector_size=self._sector_size, source_path=self.image_path, is_readonly=True)

    def get_size(self) -> int:
        return self._disk_size

    def close(self):
        if self._vdi and hasattr(self._vdi, 'close'):
            try: self._vdi.close()
            except Exception: pass
        self._vdi = None
        if self._fh:
            try: self._fh.close()
            except Exception: pass
            self._fh = None
        self._is_open = False


# ==============================================================================
# DMG (Apple UDIF) Backend — cross-platform, pure Python
# ==============================================================================

class _BLKXChunkEntry(NamedTuple):
    """Single chunk entry from a BLKXTable (mish block)."""
    entry_type: int          # Compression type
    sector_number: int       # Starting sector (absolute within partition)
    sector_count: int        # Number of 512-byte sectors
    compressed_offset: int   # Offset into the DMG data fork
    compressed_length: int   # Compressed data length in bytes


class DMGDiskBackend(UnifiedDiskReader):
    """
    Apple DMG (UDIF) disk image backend — cross-platform, pure Python

    Parses the UDIF koly trailer, XML plist resource fork, and BLKXTable
    block maps to provide transparent random-access reads over compressed
    DMG images.  Supports zlib, bz2, raw, and zero-fill chunk types.
    LZFSE is logged as a warning (requires optional ``lzfse`` package).

    No external dependencies beyond the Python standard library (zlib and
    bz2 are stdlib; plistlib is stdlib).

    Usage:
        with DMGDiskBackend("macos.dmg") as disk:
            mbr = disk.read(0, 512)
    """

    # Chunk entry_type constants
    _CT_ZERO        = 0x00000000   # Zero-fill
    _CT_RAW         = 0x00000001   # Uncompressed (raw copy)
    _CT_IGNORE      = 0x00000002   # Ignorable / zero-fill
    _CT_ZLIB        = 0x80000005   # zlib compressed
    _CT_BZ2         = 0x80000006   # bz2 compressed
    _CT_LZFSE       = 0x80000007   # LZFSE compressed (Apple)
    _CT_LZMA        = 0x80000008   # LZMA compressed (rare)
    _CT_COMMENT     = 0x7FFFFFFE   # Comment / ignore
    _CT_END         = 0xFFFFFFFF   # End-of-table marker

    # UDIF koly magic
    _KOLY_MAGIC     = b'koly'
    _KOLY_SIZE      = 512

    # BLKXTable (mish) magic
    _MISH_MAGIC     = b'mish'

    # Sector size (always 512 for DMG)
    _SECTOR_SIZE    = 512

    # Decompressed chunk LRU cache — cap at ~64 MB worth of entries
    _CACHE_MAX_BYTES = 64 * 1024 * 1024

    def __init__(self, dmg_path: str):
        """
        Args:
            dmg_path: Path to DMG image file
        """
        super().__init__()
        self.image_path = dmg_path
        self._fh = None

        # Sorted list of (_BLKXChunkEntry, absolute_sector_start) for bisect
        self._sector_map: List[Tuple[int, _BLKXChunkEntry]] = []

        # LRU cache: key = (compressed_offset, compressed_length) -> decompressed bytes
        self._chunk_cache: OrderedDict = OrderedDict()
        self._cache_bytes = 0

        self._lzfse_available = False

        self._open()

    # ------------------------------------------------------------------
    # Open / parse
    # ------------------------------------------------------------------

    def _open(self):
        if not os.path.exists(self.image_path):
            raise DiskNotFoundError(f"DMG file not found: {self.image_path}")

        try:
            logger.info(f"Opening DMG image: {self.image_path}")
            self._fh = open(self.image_path, 'rb')

            # 1. Read koly trailer (last 512 bytes)
            koly = self._read_koly_trailer()

            # 2. Read XML plist
            self._fh.seek(koly['xml_offset'])
            xml_data = self._fh.read(koly['xml_length'])
            if not xml_data:
                raise DiskError("DMG XML plist is empty")

            # 3. Parse plist -> list of BLKXChunkEntry per partition
            all_chunks = self._parse_xml_plist(xml_data)

            # 4. Build sorted sector map
            self._build_sector_map(all_chunks)

            # 5. Compute virtual disk size
            if self._sector_map:
                last_start, last_chunk = self._sector_map[-1]
                self._disk_size = (last_start + last_chunk.sector_count) * self._SECTOR_SIZE
            else:
                self._disk_size = 0

            self._sector_size = self._SECTOR_SIZE
            self._is_open = True

            # Check LZFSE availability
            try:
                import lzfse as _lzfse  # noqa: F401
                self._lzfse_available = True
            except ImportError:
                self._lzfse_available = False

            logger.info(
                f"DMG image opened: {self._disk_size / (1024**3):.2f} GB, "
                f"{len(self._sector_map)} chunk entries"
            )

        except DiskError:
            raise
        except Exception as e:
            if self._fh:
                self._fh.close()
                self._fh = None
            raise DiskError(f"Failed to open DMG: {e}")

    def _read_koly_trailer(self) -> dict:
        """
        Read and parse the UDIF koly trailer (last 512 bytes).

        Returns:
            dict with keys: version, header_size, flags,
            data_fork_offset, data_fork_length, xml_offset, xml_length,
            sector_count, etc.
        """
        self._fh.seek(0, 2)
        file_size = self._fh.tell()
        if file_size < self._KOLY_SIZE:
            raise DiskError(f"File too small to be a DMG ({file_size} bytes)")

        self._fh.seek(file_size - self._KOLY_SIZE)
        trailer = self._fh.read(self._KOLY_SIZE)
        if len(trailer) < self._KOLY_SIZE:
            raise DiskError("Failed to read koly trailer")

        magic = trailer[0:4]
        if magic != self._KOLY_MAGIC:
            raise DiskError(
                f"Invalid DMG koly magic: {magic!r} (expected {self._KOLY_MAGIC!r}). "
                "File may not be a UDIF DMG or may be corrupted."
            )

        # Parse koly fields (all big-endian)
        #  0: magic(4)    4: version(4)    8: header_size(4)    12: flags(4)
        # 16: running_data_fork_offset(8)  24: data_fork_offset(8)
        # 32: data_fork_length(8)          40: rsrc_fork_offset(8)
        # 48: rsrc_fork_length(8)          56: segment_number(4)
        # 60: segment_count(4)             64: segment_id(16)
        # 80: data_checksum_type(4)        84: data_checksum_size(4)
        # 88: data_checksum(128)
        # 216: xml_offset(8)              224: xml_length(8)
        # 232: reserved(120)
        # 352: checksum_type(4)           356: checksum_size(4)
        # 360: checksum(128)
        # 488: image_variant(4)           492: sector_count(8)
        # 500: reserved(12)

        version      = struct.unpack('>I', trailer[4:8])[0]
        header_size  = struct.unpack('>I', trailer[8:12])[0]
        flags        = struct.unpack('>I', trailer[12:16])[0]

        data_fork_offset = struct.unpack('>Q', trailer[24:32])[0]
        data_fork_length = struct.unpack('>Q', trailer[32:40])[0]

        xml_offset   = struct.unpack('>Q', trailer[216:224])[0]
        xml_length   = struct.unpack('>Q', trailer[224:232])[0]

        sector_count = struct.unpack('>Q', trailer[492:500])[0]

        if xml_length == 0:
            raise DiskError(
                "DMG has no XML plist (xml_length=0). "
                "Resource-fork-only DMGs are not supported."
            )

        if xml_offset + xml_length > file_size:
            raise DiskError(
                f"XML plist range ({xml_offset}..{xml_offset + xml_length}) "
                f"exceeds file size ({file_size})"
            )

        return {
            'version': version,
            'header_size': header_size,
            'flags': flags,
            'data_fork_offset': data_fork_offset,
            'data_fork_length': data_fork_length,
            'xml_offset': xml_offset,
            'xml_length': xml_length,
            'sector_count': sector_count,
        }

    def _parse_xml_plist(self, xml_data: bytes) -> List[List[_BLKXChunkEntry]]:
        """
        Parse the XML plist to extract blkx (BLKXTable) resource entries.

        Returns:
            List of partition chunk lists, where each inner list is a
            sorted list of _BLKXChunkEntry for one blkx partition.
        """
        try:
            plist = plistlib.loads(xml_data)
        except Exception as e:
            raise DiskError(f"Failed to parse DMG XML plist: {e}")

        # The plist root is a dict.  blkx data lives under:
        #   resource-fork -> blkx -> [array of dicts with 'Data' key]
        # OR at top level in some DMGs:
        #   resource-fork -> blkx -> [...]
        blkx_list = None

        if isinstance(plist, dict):
            rf = plist.get('resource-fork', plist)
            if isinstance(rf, dict):
                blkx_list = rf.get('blkx')

        if not blkx_list:
            raise DiskError("No 'blkx' entries found in DMG plist")

        if not isinstance(blkx_list, list):
            raise DiskError(f"Expected blkx to be a list, got {type(blkx_list).__name__}")

        all_partitions = []

        for idx, entry in enumerate(blkx_list):
            if not isinstance(entry, dict):
                continue

            # The binary BLKXTable data
            blkx_data = entry.get('Data')
            if blkx_data is None:
                continue

            # plistlib may return bytes directly or we may need base64 decode
            if isinstance(blkx_data, bytes):
                raw = blkx_data
            elif isinstance(blkx_data, str):
                try:
                    raw = base64.b64decode(blkx_data)
                except Exception:
                    logger.warning(f"DMG: Failed to base64-decode blkx entry {idx}")
                    continue
            else:
                continue

            try:
                chunks = self._parse_blkx_table(raw)
                if chunks:
                    all_partitions.append(chunks)
            except Exception as e:
                logger.warning(f"DMG: Failed to parse blkx table {idx}: {e}")
                continue

        if not all_partitions:
            raise DiskError("No valid BLKXTable entries found in DMG")

        return all_partitions

    def _parse_blkx_table(self, data: bytes) -> List[_BLKXChunkEntry]:
        """
        Parse a single BLKXTable (mish block).

        BLKXTable header (200 bytes):
            0: signature(4) = 'mish'
            4: version(4)
            8: sector_number(8)    — first sector of this partition
           16: sector_count(8)     — total sectors in this partition
           24: data_offset(8)
           32: buffers_needed(4)
           36: block_descriptors(4)
           40: reserved(24)        — 6 × uint32
           64: checksum_type(4)
           68: checksum_size(4)
           72: checksum(128)
          200: chunk entries start

        Each chunk entry is 40 bytes:
            0: entry_type(4)
            4: comment(4)
            8: sector_number(8)      — sector offset relative to partition start
           16: sector_count(8)
           24: compressed_offset(8)  — absolute offset in DMG file
           32: compressed_length(8)

        Returns:
            List of _BLKXChunkEntry with sector_number converted to
            absolute sectors (partition_start + relative).
        """
        if len(data) < 204:
            raise DiskError(f"BLKXTable too short ({len(data)} bytes)")

        sig = data[0:4]
        if sig != self._MISH_MAGIC:
            raise DiskError(f"Invalid BLKXTable magic: {sig!r}")

        partition_sector_start = struct.unpack('>Q', data[8:16])[0]

        # Number of chunk entries
        block_descriptors = struct.unpack('>I', data[36:40])[0]

        header_size = 200
        entry_size = 40
        expected = header_size + block_descriptors * entry_size
        if len(data) < expected:
            # Some DMGs have trailing data; only warn if significantly short
            available_entries = (len(data) - header_size) // entry_size
            if available_entries <= 0:
                raise DiskError("BLKXTable has no chunk entries")
            block_descriptors = available_entries
            logger.debug(
                f"DMG: BLKXTable truncated, using {block_descriptors} entries"
            )

        chunks = []
        offset = header_size

        for i in range(block_descriptors):
            if offset + entry_size > len(data):
                break

            entry_type       = struct.unpack('>I', data[offset:offset+4])[0]
            # comment at offset+4 (4 bytes) — unused
            rel_sector_num   = struct.unpack('>Q', data[offset+8:offset+16])[0]
            sector_count     = struct.unpack('>Q', data[offset+16:offset+24])[0]
            compressed_off   = struct.unpack('>Q', data[offset+24:offset+32])[0]
            compressed_len   = struct.unpack('>Q', data[offset+32:offset+40])[0]

            offset += entry_size

            # Skip end markers and comments
            if entry_type == self._CT_END:
                break
            if entry_type == self._CT_COMMENT:
                continue

            # Absolute sector number = partition start + relative
            abs_sector = partition_sector_start + rel_sector_num

            chunks.append(_BLKXChunkEntry(
                entry_type=entry_type,
                sector_number=abs_sector,
                sector_count=sector_count,
                compressed_offset=compressed_off,
                compressed_length=compressed_len,
            ))

        return chunks

    def _build_sector_map(self, all_partitions: List[List[_BLKXChunkEntry]]):
        """
        Build a flat, sorted sector map from all partition chunk lists.

        The map is a list of (absolute_sector_start, _BLKXChunkEntry)
        sorted by sector start, enabling O(log n) lookup via bisect.
        """
        flat = []
        for partition_chunks in all_partitions:
            for chunk in partition_chunks:
                if chunk.sector_count > 0:
                    flat.append((chunk.sector_number, chunk))

        # Sort by sector start.  Stable sort preserves partition order for
        # equal sector numbers (shouldn't happen in valid DMGs).
        flat.sort(key=lambda x: x[0])
        self._sector_map = flat

    # ------------------------------------------------------------------
    # Read interface
    # ------------------------------------------------------------------

    _MAX_READ_CHUNK = 8 * 1024 * 1024  # 8 MB max single decompressed chunk

    def read(self, offset: int, size: int) -> bytes:
        """
        Read *size* bytes starting at byte *offset* in the virtual disk.

        Handles reads spanning multiple compressed chunks transparently.
        """
        if not self._is_open:
            raise DiskError("DMG not open")

        if size <= 0:
            return b''
        if offset < 0:
            raise DiskReadError(f"Negative offset: {offset}")
        if offset >= self._disk_size:
            return b''

        # Clamp to disk size
        end = min(offset + size, self._disk_size)
        size = end - offset

        result = bytearray()
        pos = offset

        while pos < end:
            sector_num = pos // self._SECTOR_SIZE
            offset_in_sector = pos % self._SECTOR_SIZE

            # Find the chunk containing this sector
            chunk = self._find_chunk(sector_num)
            if chunk is None:
                # Unmapped region — treat as zeros
                # Advance to next chunk start or to end
                next_start = self._next_chunk_start_after(sector_num)
                if next_start is not None:
                    zero_end = min(next_start * self._SECTOR_SIZE, end)
                else:
                    zero_end = end
                zero_bytes = zero_end - pos
                result.extend(b'\x00' * zero_bytes)
                pos += zero_bytes
                continue

            # Decompress the chunk (cached)
            decompressed = self._decompress_chunk(chunk)

            # Calculate position within decompressed data
            chunk_byte_start = chunk.sector_number * self._SECTOR_SIZE
            pos_in_chunk = pos - chunk_byte_start
            available = len(decompressed) - pos_in_chunk
            want = min(end - pos, available)

            if want <= 0:
                # Edge case: decompressed data shorter than expected
                # Pad with zeros for the missing part
                chunk_byte_end = chunk_byte_start + chunk.sector_count * self._SECTOR_SIZE
                pad = min(end - pos, chunk_byte_end - pos)
                result.extend(b'\x00' * max(pad, 1))
                pos += max(pad, 1)
                continue

            result.extend(decompressed[pos_in_chunk:pos_in_chunk + want])
            pos += want

        return bytes(result)

    def _find_chunk(self, sector_num: int) -> Optional[_BLKXChunkEntry]:
        """
        Find the BLKXChunkEntry that contains *sector_num*.

        Uses binary search (bisect) for O(log n) lookup.
        The sector map contains (sector_start, _BLKXChunkEntry) tuples.
        We use (sector_num + 1,) as the search key so bisect_right lands
        *after* any entry whose sector_start equals sector_num (tuple
        comparison means (N,) < (N, chunk) for any chunk).
        """
        if not self._sector_map:
            return None

        # Find the rightmost entry whose sector_start <= sector_num.
        # Using (sector_num + 1,) ensures we go past entries that start
        # exactly at sector_num, so idx-1 gives the correct candidate.
        idx = bisect.bisect_right(self._sector_map, (sector_num + 1,)) - 1
        if idx < 0:
            return None

        start, chunk = self._sector_map[idx]
        if start <= sector_num < start + chunk.sector_count:
            return chunk
        return None

    def _next_chunk_start_after(self, sector_num: int) -> Optional[int]:
        """Return the sector_number of the first chunk starting after *sector_num*."""
        idx = bisect.bisect_right(self._sector_map, (sector_num + 1,))
        if idx < len(self._sector_map):
            return self._sector_map[idx][0]
        return None

    # ------------------------------------------------------------------
    # Decompression + cache
    # ------------------------------------------------------------------

    def _decompress_chunk(self, chunk: _BLKXChunkEntry) -> bytes:
        """
        Decompress a single chunk, using an LRU cache.

        Returns the full decompressed data for the chunk
        (sector_count * 512 bytes for non-compressed types).
        """
        cache_key = (chunk.compressed_offset, chunk.compressed_length, chunk.entry_type)

        if cache_key in self._chunk_cache:
            # Move to end (most recently used)
            self._chunk_cache.move_to_end(cache_key)
            return self._chunk_cache[cache_key]

        expected_size = chunk.sector_count * self._SECTOR_SIZE
        entry_type = chunk.entry_type

        if entry_type in (self._CT_ZERO, self._CT_IGNORE):
            data = b'\x00' * expected_size

        elif entry_type == self._CT_RAW:
            data = self._read_compressed_data(chunk)
            # Pad or trim to expected size
            if len(data) < expected_size:
                data = data + b'\x00' * (expected_size - len(data))
            elif len(data) > expected_size:
                data = data[:expected_size]

        elif entry_type == self._CT_ZLIB:
            compressed = self._read_compressed_data(chunk)
            try:
                data = zlib.decompress(compressed)
            except zlib.error as e:
                logger.warning(
                    f"DMG: zlib decompression failed at offset "
                    f"{chunk.compressed_offset}: {e}. Returning zeros."
                )
                data = b'\x00' * expected_size
            # Pad/trim
            if len(data) < expected_size:
                data = data + b'\x00' * (expected_size - len(data))
            elif len(data) > expected_size:
                data = data[:expected_size]

        elif entry_type == self._CT_BZ2:
            compressed = self._read_compressed_data(chunk)
            try:
                data = bz2.decompress(compressed)
            except (OSError, ValueError) as e:
                logger.warning(
                    f"DMG: bz2 decompression failed at offset "
                    f"{chunk.compressed_offset}: {e}. Returning zeros."
                )
                data = b'\x00' * expected_size
            if len(data) < expected_size:
                data = data + b'\x00' * (expected_size - len(data))
            elif len(data) > expected_size:
                data = data[:expected_size]

        elif entry_type == self._CT_LZFSE:
            if self._lzfse_available:
                compressed = self._read_compressed_data(chunk)
                try:
                    import lzfse
                    data = lzfse.decompress(compressed)
                except Exception as e:
                    logger.warning(
                        f"DMG: LZFSE decompression failed at offset "
                        f"{chunk.compressed_offset}: {e}. Returning zeros."
                    )
                    data = b'\x00' * expected_size
            else:
                logger.warning(
                    f"DMG: LZFSE compressed chunk encountered at offset "
                    f"{chunk.compressed_offset} but 'lzfse' package not installed. "
                    f"Install with: pip install lzfse. Returning zeros."
                )
                data = b'\x00' * expected_size
            if len(data) < expected_size:
                data = data + b'\x00' * (expected_size - len(data))
            elif len(data) > expected_size:
                data = data[:expected_size]

        elif entry_type == self._CT_LZMA:
            compressed = self._read_compressed_data(chunk)
            try:
                import lzma
                data = lzma.decompress(compressed)
            except Exception as e:
                logger.warning(
                    f"DMG: LZMA decompression failed at offset "
                    f"{chunk.compressed_offset}: {e}. Returning zeros."
                )
                data = b'\x00' * expected_size
            if len(data) < expected_size:
                data = data + b'\x00' * (expected_size - len(data))
            elif len(data) > expected_size:
                data = data[:expected_size]

        else:
            logger.warning(
                f"DMG: Unknown chunk type 0x{entry_type:08X} at offset "
                f"{chunk.compressed_offset}. Returning zeros."
            )
            data = b'\x00' * expected_size

        # Insert into LRU cache
        self._chunk_cache[cache_key] = data
        self._cache_bytes += len(data)

        # Evict oldest entries if cache exceeds limit
        while self._cache_bytes > self._CACHE_MAX_BYTES and self._chunk_cache:
            _, evicted = self._chunk_cache.popitem(last=False)
            self._cache_bytes -= len(evicted)

        return data

    def _read_compressed_data(self, chunk: _BLKXChunkEntry) -> bytes:
        """Read raw compressed data from the DMG file."""
        if chunk.compressed_length <= 0:
            return b''
        self._fh.seek(chunk.compressed_offset)
        data = self._fh.read(chunk.compressed_length)
        if len(data) < chunk.compressed_length:
            logger.warning(
                f"DMG: Short read at offset {chunk.compressed_offset}: "
                f"expected {chunk.compressed_length}, got {len(data)}"
            )
        return data

    # ------------------------------------------------------------------
    # UnifiedDiskReader interface
    # ------------------------------------------------------------------

    def get_disk_info(self) -> DiskInfo:
        return DiskInfo(
            source_type=DiskSourceType.DMG_IMAGE,
            total_size=self._disk_size,
            sector_size=self._sector_size,
            source_path=self.image_path,
            is_readonly=True,
        )

    def get_size(self) -> int:
        return self._disk_size

    def close(self):
        self._chunk_cache.clear()
        self._cache_bytes = 0
        self._sector_map = []
        if self._fh:
            try:
                self._fh.close()
                logger.debug(f"Closed DMG image: {self.image_path}")
            except Exception as e:
                logger.warning(f"Error closing DMG: {e}")
            finally:
                self._fh = None
                self._is_open = False


# ==============================================================================
# RAW Image Backend
# ==============================================================================

class RAWImageBackend(UnifiedDiskReader):
    """
    RAW/DD image file backend

    Accesses raw disk image files created with dd.

    Features:
    - Simple file I/O
    - Supports .dd, .raw, .img, .bin, etc.
    - Memory mapping option (for large files)

    Usage:
        with RAWImageBackend("disk.dd") as disk:
            mbr = disk.read(0, 512)
    """

    def __init__(self, image_path: str, use_mmap: bool = False):
        """
        Args:
            image_path: RAW image file path
            use_mmap: Whether to use memory mapping (useful for large files)
        """
        super().__init__()

        self.image_path = image_path
        self._file = None
        self._mmap = None
        self._use_mmap = use_mmap

        self._open()

    def _open(self):
        """Open image file"""
        if not os.path.exists(self.image_path):
            raise DiskNotFoundError(f"Image file not found: {self.image_path}")

        try:
            logger.info(f"Opening RAW image: {self.image_path}")

            self._file = open(self.image_path, 'rb')

            # Get file size
            self._file.seek(0, 2)
            self._disk_size = self._file.tell()
            self._file.seek(0)

            # Memory mapping (optional)
            if self._use_mmap and self._disk_size > 0:
                import mmap
                self._mmap = mmap.mmap(
                    self._file.fileno(),
                    0,
                    access=mmap.ACCESS_READ
                )

            self._sector_size = 512
            self._is_open = True
            logger.info(f"RAW image opened: {self._disk_size / (1024**3):.2f} GB")

        except Exception as e:
            raise DiskError(f"Failed to open RAW image: {e}")

    def read(self, offset: int, size: int) -> bytes:
        """Read raw bytes"""
        if not self._is_open:
            raise DiskError("Image not open")

        try:
            if self._mmap:
                # Use memory mapping
                end = min(offset + size, self._disk_size)
                return bytes(self._mmap[offset:end])
            else:
                # Normal file I/O
                self._file.seek(offset)
                return self._file.read(size)
        except Exception as e:
            raise DiskReadError(f"RAW read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        """Return disk metadata"""
        return DiskInfo(
            source_type=DiskSourceType.RAW_IMAGE,
            total_size=self._disk_size,
            sector_size=self._sector_size,
            source_path=self.image_path,
            is_readonly=True
        )

    def get_size(self) -> int:
        """Get total disk size"""
        return self._disk_size

    def close(self):
        """Release resources"""
        if self._mmap:
            try:
                self._mmap.close()
            except Exception:
                pass
            self._mmap = None

        if self._file:
            try:
                self._file.close()
                logger.debug(f"Closed RAW image: {self.image_path}")
            except Exception:
                pass
            self._file = None

        self._is_open = False


# ==============================================================================
# Factory Function
# ==============================================================================

def create_disk_backend(source: str) -> UnifiedDiskReader:
    """
    Auto-create disk backend

    Automatically detects source type and creates appropriate backend.

    Args:
        source: Disk source
            - Numeric string: Physical drive number (e.g., "0", "1")
            - .e01/.ex01 file: E01 image
            - Other files: RAW image

    Returns:
        UnifiedDiskReader instance

    Usage:
        with create_disk_backend("0") as disk:  # PhysicalDrive0
            ...

        with create_disk_backend("evidence.E01") as disk:  # E01
            ...
    """
    source = str(source)

    # Numeric = physical drive
    if source.isdigit():
        return PhysicalDiskBackend(int(source))

    # Check file extension
    ext = Path(source).suffix.lower()

    if ext in ('.e01', '.ex01', '.s01', '.l01'):
        return E01DiskBackend(source)
    elif ext == '.vmdk':
        return VMDKDiskBackend(source)
    elif ext == '.vhd':
        return VHDDiskBackend(source)
    elif ext == '.vhdx':
        return VHDXDiskBackend(source)
    elif ext == '.qcow2':
        return QCOW2DiskBackend(source)
    elif ext == '.vdi':
        return VDIDiskBackend(source)
    elif ext == '.dmg':
        # Try UDIF first; fall back to RAW for uncompressed .dmg images
        try:
            return DMGDiskBackend(source)
        except (DiskError, Exception) as e:
            logger.info(f"DMG is not UDIF format ({e}), opening as RAW image")
            return RAWImageBackend(source)
    else:
        return RAWImageBackend(source)


# ==============================================================================
# Test
# ==============================================================================

if __name__ == '__main__':
    import sys

    print("=" * 60)
    print("Disk Backend Test")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python disk_backends.py 0              # PhysicalDrive0")
        print("  python disk_backends.py evidence.E01   # E01 image")
        print("  python disk_backends.py disk.dd        # RAW image")
        sys.exit(1)

    source = sys.argv[1]

    try:
        with create_disk_backend(source) as disk:
            info = disk.get_disk_info()
            print(f"\n[Disk Info]")
            print(f"  Type: {info.source_type.value}")
            print(f"  Size: {info.total_size / (1024**3):.2f} GB")
            print(f"  Sector Size: {info.sector_size} bytes")
            print(f"  Path: {info.source_path}")

            # Read MBR
            print(f"\n[MBR Test]")
            mbr = disk.read(0, 512)
            print(f"  Read {len(mbr)} bytes")

            # Check MBR signature
            if len(mbr) >= 512:
                signature = struct.unpack('<H', mbr[510:512])[0]
                print(f"  MBR Signature: 0x{signature:04X} ({'OK' if signature == 0xAA55 else 'INVALID'})")

                # Check partition types
                for i in range(4):
                    ptype = mbr[446 + i*16 + 4]
                    if ptype != 0:
                        print(f"  Partition {i}: Type 0x{ptype:02X}")

            print("\n[Test Complete]")

    except Exception as e:
        print(f"\n[Error] {e}")
        import traceback
        traceback.print_exc()
