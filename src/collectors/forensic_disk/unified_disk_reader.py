# -*- coding: utf-8 -*-
"""
Unified Disk Reader - Abstract Base Class for Raw Disk Access

Unified interface for all disk sources (physical disk, E01, RAW image).
Same raw sector based access approach as FTK Imager, Autopsy, EnCase.

Features:
- Direct physical disk access (\\\\.\\PhysicalDrive{N})
- E01 forensic images (pyewf)
- RAW/DD image files
- Automatic sector alignment handling

Usage:
    from core.engine.collectors.filesystem.unified_disk_reader import UnifiedDiskReader
    from core.engine.collectors.filesystem.disk_backends import PhysicalDiskBackend

    with PhysicalDiskBackend(0) as disk:
        # Read MBR
        mbr = disk.read(0, 512)

        # Read specific sectors
        data = disk.read_sectors(2048, 8)  # 8 sectors starting from sector 2048

References:
- https://docs.microsoft.com/en-us/windows/win32/fileio/disk-devices
- https://github.com/libyal/libewf
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class DiskSourceType(Enum):
    """Disk source type"""
    PHYSICAL_DISK = "physical"    # \\.\PhysicalDrive{N}
    E01_IMAGE = "e01"             # E01/EWF forensic image
    RAW_IMAGE = "raw"             # DD/RAW image file
    VHD_IMAGE = "vhd"             # Virtual Hard Disk
    VMDK_IMAGE = "vmdk"           # VMware Disk


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
    partition_type: int           # MBR type (0x07=NTFS, 0x0B=FAT32, etc.)
    type_guid: str = ""           # GPT GUID
    type_name: str = ""           # Filesystem name
    offset: int = 0               # Partition start offset (bytes)
    size: int = 0                 # Partition size (bytes)
    lba_start: int = 0            # Starting LBA sector
    sector_count: int = 0         # Number of sectors
    filesystem: str = ""          # Detected filesystem (NTFS, FAT32, etc.)
    is_bootable: bool = False     # Bootable flag
    name: str = ""                # GPT partition name


class UnifiedDiskReader(ABC):
    """
    Unified Disk Reader Abstract Base Class

    All disk sources (physical disk, E01, RAW, etc.) implement this interface.
    Raw sector based access completely bypasses the Windows filesystem.

    Usage:
        # Using context manager (recommended)
        with PhysicalDiskBackend(0) as disk:
            data = disk.read(0, 512)

        # Direct usage
        disk = PhysicalDiskBackend(0)
        try:
            data = disk.read(0, 512)
        finally:
            disk.close()
    """

    def __init__(self):
        self._sector_size = 512
        self._disk_size = 0
        self._is_open = False

    # ========== Abstract Methods (must implement) ==========

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """
        Read raw bytes

        Args:
            offset: Absolute byte offset (from disk start)
            size: Number of bytes to read

        Returns:
            Raw byte data (may be less than size at disk end)

        Raises:
            IOError: Read failed
        """
        pass

    @abstractmethod
    def get_disk_info(self) -> DiskInfo:
        """Return disk metadata"""
        pass

    @abstractmethod
    def get_size(self) -> int:
        """Get total disk size (bytes)"""
        pass

    @abstractmethod
    def close(self) -> None:
        """Release resources"""
        pass

    # ========== Implemented Methods ==========

    def read_sectors(self, sector_offset: int, sector_count: int) -> bytes:
        """
        Read by sector units

        Args:
            sector_offset: Starting sector number (0-based)
            sector_count: Number of sectors to read

        Returns:
            Raw sector data
        """
        byte_offset = sector_offset * self._sector_size
        byte_size = sector_count * self._sector_size
        return self.read(byte_offset, byte_size)

    def read_aligned(self, offset: int, size: int) -> bytes:
        """
        Sector-aligned read

        Physical disks require reads aligned to sector boundaries.
        This method automatically handles alignment.

        Args:
            offset: Byte offset (alignment not required)
            size: Number of bytes to read

        Returns:
            Data of the requested range (exact size)
        """
        # Calculate aligned start/end sectors
        start_sector = offset // self._sector_size
        end_byte = offset + size
        end_sector = (end_byte + self._sector_size - 1) // self._sector_size

        # Read aligned data
        aligned_data = self.read_sectors(start_sector, end_sector - start_sector)

        # Extract requested range
        start_in_sector = offset % self._sector_size
        return aligned_data[start_in_sector:start_in_sector + size]

    def read_cluster(self, cluster_number: int, cluster_size: int, partition_offset: int = 0) -> bytes:
        """
        Read cluster (filesystem level)

        Args:
            cluster_number: Cluster number (LCN)
            cluster_size: Cluster size (bytes)
            partition_offset: Partition start offset

        Returns:
            Cluster data
        """
        offset = partition_offset + (cluster_number * cluster_size)
        return self.read(offset, cluster_size)

    def read_clusters(
        self,
        data_runs: List[Tuple[int, int]],
        cluster_size: int,
        partition_offset: int = 0,
        max_size: int = None
    ) -> bytes:
        """
        Read file data from data runs

        Reads file contents following NTFS data runs or FAT cluster chain.

        Args:
            data_runs: [(lcn, cluster_count), ...] list
            cluster_size: Cluster size (bytes)
            partition_offset: Partition start offset
            max_size: Maximum read size (for file size limiting)

        Returns:
            File data (bytes)
        """
        data = bytearray()
        bytes_read = 0

        for lcn, cluster_count in data_runs:
            if max_size and bytes_read >= max_size:
                break

            if lcn is None:
                # Sparse run - fill with zeros
                sparse_size = cluster_count * cluster_size
                if max_size:
                    sparse_size = min(sparse_size, max_size - bytes_read)
                data.extend(b'\x00' * sparse_size)
                bytes_read += sparse_size
            else:
                # Read actual clusters
                run_offset = partition_offset + (lcn * cluster_size)
                run_size = cluster_count * cluster_size

                if max_size:
                    run_size = min(run_size, max_size - bytes_read)

                chunk = self.read(run_offset, run_size)
                data.extend(chunk)
                bytes_read += len(chunk)

        if max_size:
            return bytes(data[:max_size])
        return bytes(data)

    @property
    def sector_size(self) -> int:
        """Sector size (typically 512 bytes)"""
        return self._sector_size

    @property
    def is_open(self) -> bool:
        """Whether the disk is open"""
        return self._is_open

    # ========== Context Manager ==========

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class DiskError(Exception):
    """Base exception for disk operations"""
    pass


class DiskNotFoundError(DiskError):
    """Disk not found"""
    pass


class DiskPermissionError(DiskError):
    """Disk access permission denied (administrator privileges required)"""
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
