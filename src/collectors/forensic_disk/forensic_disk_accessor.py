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
- Automatic filesystem detection (NTFS, FAT32, exFAT)
- MFT/FAT based file reading
- Deleted file recovery
- ADS (Alternate Data Streams) support

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

    # Full scan including deleted files
    catalog = disk.scan_all_files(include_deleted=True)
"""

import struct
import logging
from typing import Optional, List, Dict, Generator, Any, Union, Tuple
from pathlib import Path
from dataclasses import dataclass

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
                except:
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

        # Create FileContentExtractor
        # Supported filesystems: NTFS, FAT, exFAT, ext2/3/4, APFS, HFS+
        supported_fs = (
            'NTFS', 'FAT32', 'FAT16', 'FAT12', 'exFAT',  # Windows/Universal
            'ext2', 'ext3', 'ext4',  # Linux
            'APFS', 'HFS+', 'HFSX', 'HFS'  # macOS
        )

        if partition.filesystem in supported_fs:
            self._extractor = FileContentExtractor(
                disk=self._backend,
                partition_offset=partition.offset,
                fs_type=partition.filesystem
            )
            logger.info(f"Selected partition {index}: {partition.filesystem} at offset {partition.offset}")
        else:
            self._extractor = None
            logger.warning(f"Unsupported filesystem: {partition.filesystem}")

        # Initialize cache
        self._path_cache.clear()

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
        Read file by MFT entry number

        Args:
            inode: MFT entry number
            stream_name: ADS name (e.g., "Zone.Identifier")
            max_size: Maximum read size

        Returns:
            File content (bytes)
        """
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
        Stream large file by MFT entry

        Args:
            inode: MFT entry number
            stream_name: ADS name
            chunk_size: Chunk size

        Yields:
            File data chunks
        """
        if self._extractor is None:
            raise FilesystemError("No partition selected")

        yield from self._extractor.stream_file_by_inode(inode, stream_name, chunk_size)

    def get_file_metadata(self, inode: int) -> FileMetadata:
        """
        Get file metadata

        Args:
            inode: MFT entry number

        Returns:
            FileMetadata object
        """
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
        """
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
                    metadata = self._extractor.get_file_metadata(entry_num)

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

            self._parent_index_built = True
            logger.info(f"MFT parent-child index built: {len(self._parent_child_index)} parent directories, {indexed_count} files indexed")

        except Exception as e:
            logger.warning(f"Failed to build parent index: {e}")
            self._parent_child_index = {}
            self._name_to_inode_map = {}

    def list_directory(self, path: str) -> List[FileCatalogEntry]:
        """
        List directory contents (index-based O(1) lookup)

        Args:
            path: Directory path

        Returns:
            List of FileCatalogEntry
        """
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
        Full MFT scan (including deleted files)

        Digital forensics principles:
        - include_deleted=True (default): Include deleted files
        - max_entries=None (default): No limit, scan entire MFT

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
                'special_files': Dict[str, int],  # inode for $MFT, $LogFile, etc.
            }
        """
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

                # Extract metadata
                try:
                    metadata = self._extractor.get_file_metadata(entry_num)
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
    # Special Files
    # ==========================================================================

    def read_mft_raw(self, max_size: int = None) -> bytes:
        """
        Read $MFT file raw data

        Args:
            max_size: Maximum size (None = all)

        Returns:
            MFT raw data
        """
        return self.read_file_by_inode(0, max_size=max_size)

    def read_logfile_raw(self, max_size: int = None) -> bytes:
        """
        Read $LogFile raw data (NTFS transaction log)
        """
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
