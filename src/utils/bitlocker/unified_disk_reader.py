# -*- coding: utf-8 -*-
"""
Unified Disk Reader - Abstract Base Class for Raw Disk Access

Unified interface for all disk sources (physical disks, E01, RAW images).
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class DiskSourceType(Enum):
    """Disk source type"""
    PHYSICAL_DISK = "physical"
    E01_IMAGE = "e01"
    RAW_IMAGE = "raw"
    VHD_IMAGE = "vhd"
    VMDK_IMAGE = "vmdk"
    VHDX_IMAGE = "vhdx"
    QCOW2_IMAGE = "qcow2"
    VDI_IMAGE = "vdi"


@dataclass
class DiskInfo:
    """Disk metadata"""
    source_type: DiskSourceType
    total_size: int
    sector_size: int = 512
    source_path: str = ""
    is_readonly: bool = True
    model: str = ""
    serial: str = ""


@dataclass
class PartitionInfo:
    """Partition information"""
    index: int
    partition_type: int
    type_guid: str = ""
    type_name: str = ""
    offset: int = 0
    size: int = 0
    lba_start: int = 0
    sector_count: int = 0
    filesystem: str = ""
    is_bootable: bool = False
    name: str = ""


class UnifiedDiskReader(ABC):
    """
    Unified disk reader abstract base class
    """

    def __init__(self):
        self._sector_size = 512
        self._disk_size = 0
        self._is_open = False

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """Read raw bytes"""
        pass

    @abstractmethod
    def get_disk_info(self) -> DiskInfo:
        """Return disk metadata"""
        pass

    @abstractmethod
    def get_size(self) -> int:
        """Disk total size (bytes)"""
        pass

    @abstractmethod
    def close(self) -> None:
        """Release resources"""
        pass

    def read_sectors(self, sector_offset: int, sector_count: int) -> bytes:
        """Read by sector unit"""
        byte_offset = sector_offset * self._sector_size
        byte_size = sector_count * self._sector_size
        return self.read(byte_offset, byte_size)

    def read_aligned(self, offset: int, size: int) -> bytes:
        """Read with sector alignment"""
        start_sector = offset // self._sector_size
        end_byte = offset + size
        end_sector = (end_byte + self._sector_size - 1) // self._sector_size
        aligned_data = self.read_sectors(start_sector, end_sector - start_sector)
        start_in_sector = offset % self._sector_size
        return aligned_data[start_in_sector:start_in_sector + size]

    @property
    def sector_size(self) -> int:
        return self._sector_size

    @property
    def is_open(self) -> bool:
        return self._is_open

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# Exception classes
class DiskError(Exception):
    """Base exception for disk operations"""
    pass


class DiskNotFoundError(DiskError):
    """Disk not found"""
    pass


class DiskPermissionError(DiskError):
    """No permission to access disk"""
    pass


class DiskReadError(DiskError):
    """Disk read error"""
    pass


class PartitionError(DiskError):
    """Partition table parsing error"""
    pass


class FilesystemError(DiskError):
    """Filesystem detection/parsing error"""
    pass


class BitLockerError(DiskError):
    """BitLocker encrypted volume"""
    pass


class BitLockerKeyRequired(BitLockerError):
    """BitLocker key required"""
    def __init__(
        self,
        message: str = "BitLocker key required",
        partition_index: int = 0,
        partition_info: 'PartitionInfo' = None,
        encryption_info: dict = None
    ):
        super().__init__(message)
        self.partition_index = partition_index
        self.partition_info = partition_info
        self.encryption_info = encryption_info or {}


class BitLockerInvalidKey(BitLockerError):
    """Invalid BitLocker key"""
    pass


class BitLockerUnsupportedProtector(BitLockerError):
    """Unsupported Key Protector"""
    pass
