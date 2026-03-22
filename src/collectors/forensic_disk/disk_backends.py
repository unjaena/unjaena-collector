# -*- coding: utf-8 -*-
"""
Disk Backends - UnifiedDiskReader implementations

Concrete implementations for three disk sources:
1. PhysicalDiskBackend - Windows physical disk (\\\\.\\PhysicalDrive{N})
2. E01DiskBackend - E01/EWF forensic image (pyewf)
3. RAWImageBackend - RAW/DD image file

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
"""

import os
import sys
import struct
import logging
from pathlib import Path
from typing import Optional, List

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

    def read(self, offset: int, size: int) -> bytes:
        if not self._is_open:
            raise DiskError("VMDK not open")
        try:
            self._vmdk.seek(offset)
            return self._vmdk.read(size)
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

    def read(self, offset: int, size: int) -> bytes:
        if not self._is_open:
            raise DiskError("VHD not open")
        try:
            self._vhd.seek(offset)
            return self._vhd.read(size)
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

    def read(self, offset: int, size: int) -> bytes:
        if not self._is_open:
            raise DiskError("VHDX not open")
        try:
            self._vhdx.seek(offset)
            return self._vhdx.read(size)
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

    def read(self, offset: int, size: int) -> bytes:
        if not self._is_open:
            raise DiskError("QCOW2 not open")
        try:
            self._qcow2.seek(offset)
            return self._qcow2.read(size)
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

    def read(self, offset: int, size: int) -> bytes:
        if not self._is_open:
            raise DiskError("VDI not open")
        try:
            self._vdi.seek(offset)
            return self._vdi.read(size)
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
