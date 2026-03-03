# -*- coding: utf-8 -*-
"""
Disk Backends - UnifiedDiskReader implementations

Provides access to physical disks, E01 images, and RAW images
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


class PhysicalDiskBackend(UnifiedDiskReader):
    """
    Windows physical disk backend
    Direct access to raw sectors via \\.\PhysicalDrive{N}
    Requires administrator privileges
    """

    def __init__(self, drive_number: int = 0):
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

            self._handle = win32file.CreateFile(
                self.drive_path,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                0,
                None
            )

            self._get_disk_geometry()
            self._is_open = True
            logger.info(f"Physical disk opened: {self._disk_size / (1024**3):.2f} GB")

        except ImportError:
            raise DiskError("pywin32 not installed. Run: pip install pywin32")
        except Exception as e:
            if hasattr(e, 'winerror'):
                error_code = e.winerror
            elif hasattr(e, 'args') and e.args:
                error_code = e.args[0]
            else:
                raise DiskError(f"Failed to open {self.drive_path}: {e}")

            if error_code == 5:
                raise DiskPermissionError(
                    f"Access denied to {self.drive_path}. Run as Administrator."
                )
            elif error_code == 2:
                raise DiskNotFoundError(f"Disk not found: {self.drive_path}")
            else:
                raise DiskError(f"Failed to open {self.drive_path}: {e}")

    def _get_disk_geometry(self):
        """Get disk geometry"""
        try:
            import win32file
            import winioctlcon

            geometry = win32file.DeviceIoControl(
                self._handle,
                winioctlcon.IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None,
                256
            )

            if len(geometry) >= 32:
                self._disk_size = struct.unpack('<Q', geometry[24:32])[0]
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

            aligned_offset = (offset // self._sector_size) * self._sector_size
            offset_in_sector = offset - aligned_offset
            aligned_size = ((offset_in_sector + size + self._sector_size - 1) //
                           self._sector_size) * self._sector_size

            win32file.SetFilePointer(self._handle, aligned_offset, win32file.FILE_BEGIN)
            _, data = win32file.ReadFile(self._handle, aligned_size)
            return bytes(data[offset_in_sector:offset_in_sector + size])

        except Exception as e:
            raise DiskReadError(f"Read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        return DiskInfo(
            source_type=DiskSourceType.PHYSICAL_DISK,
            total_size=self._disk_size,
            sector_size=self._sector_size,
            source_path=self.drive_path,
            is_readonly=True
        )

    def get_size(self) -> int:
        return self._disk_size

    def close(self):
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


class E01DiskBackend(UnifiedDiskReader):
    """E01/EWF forensic image backend"""

    def __init__(self, e01_path: str):
        super().__init__()
        self.e01_path = e01_path
        self._ewf_handle = None
        self._open()

    def _open(self):
        try:
            import pyewf

            segments = self._find_segments(self.e01_path)
            if not segments:
                raise DiskNotFoundError(f"E01 file not found: {self.e01_path}")

            logger.info(f"Opening E01 image: {self.e01_path} ({len(segments)} segments)")

            self._ewf_handle = pyewf.handle()
            self._ewf_handle.open(segments)
            self._disk_size = self._ewf_handle.get_media_size()
            self._sector_size = 512
            self._is_open = True

            logger.info(f"E01 image opened: {self._disk_size / (1024**3):.2f} GB")

        except ImportError:
            raise DiskError("pyewf not installed. Run: pip install libewf-python")
        except Exception as e:
            raise DiskError(f"Failed to open E01: {e}")

    def _find_segments(self, e01_path: str) -> List[str]:
        import glob

        e01_path = str(e01_path)
        path = Path(e01_path)

        if not path.exists():
            return []

        ext = path.suffix.lower()
        base = str(path.with_suffix(''))

        if ext.startswith('.e') and len(ext) == 4:
            pattern = f"{base}.[Ee]*"
        elif ext.startswith('.ex') or ext.startswith('.Ex'):
            pattern = f"{base}.[Ee][Xx]*"
        else:
            return [e01_path]

        segments = sorted(glob.glob(pattern))
        return segments if segments else [e01_path]

    def read(self, offset: int, size: int) -> bytes:
        if not self._is_open or not self._ewf_handle:
            raise DiskError("E01 image not open")

        try:
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)
        except Exception as e:
            raise DiskReadError(f"E01 read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        return DiskInfo(
            source_type=DiskSourceType.E01_IMAGE,
            total_size=self._disk_size,
            sector_size=self._sector_size,
            source_path=self.e01_path,
            is_readonly=True
        )

    def get_size(self) -> int:
        return self._disk_size

    def close(self):
        if self._ewf_handle:
            try:
                self._ewf_handle.close()
                logger.debug(f"Closed E01 image: {self.e01_path}")
            except Exception as e:
                logger.warning(f"Error closing E01: {e}")
            finally:
                self._ewf_handle = None
                self._is_open = False


class RAWImageBackend(UnifiedDiskReader):
    """RAW/DD image file backend"""

    def __init__(self, image_path: str, use_mmap: bool = False):
        super().__init__()
        self.image_path = image_path
        self._file = None
        self._mmap = None
        self._use_mmap = use_mmap
        self._open()

    def _open(self):
        if not os.path.exists(self.image_path):
            raise DiskNotFoundError(f"Image file not found: {self.image_path}")

        try:
            logger.info(f"Opening RAW image: {self.image_path}")

            self._file = open(self.image_path, 'rb')
            self._file.seek(0, 2)
            self._disk_size = self._file.tell()
            self._file.seek(0)

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
        if not self._is_open:
            raise DiskError("Image not open")

        try:
            if self._mmap:
                end = min(offset + size, self._disk_size)
                return bytes(self._mmap[offset:end])
            else:
                self._file.seek(offset)
                return self._file.read(size)
        except Exception as e:
            raise DiskReadError(f"RAW read failed at offset {offset}: {e}")

    def get_disk_info(self) -> DiskInfo:
        return DiskInfo(
            source_type=DiskSourceType.RAW_IMAGE,
            total_size=self._disk_size,
            sector_size=self._sector_size,
            source_path=self.image_path,
            is_readonly=True
        )

    def get_size(self) -> int:
        return self._disk_size

    def close(self):
        if self._mmap:
            try:
                self._mmap.close()
            except:
                pass
            self._mmap = None

        if self._file:
            try:
                self._file.close()
                logger.debug(f"Closed RAW image: {self.image_path}")
            except:
                pass
            self._file = None

        self._is_open = False


def create_disk_backend(source: str) -> UnifiedDiskReader:
    """Auto-create disk backend"""
    source = str(source)

    if source.isdigit():
        return PhysicalDiskBackend(int(source))

    ext = Path(source).suffix.lower()

    if ext in ('.e01', '.ex01', '.s01', '.l01'):
        return E01DiskBackend(source)
    else:
        return RAWImageBackend(source)
