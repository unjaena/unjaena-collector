# -*- coding: utf-8 -*-
"""
File Content Extractor - Data Runs based file content extraction

Uses MFT data runs or FAT cluster chain to read
file content directly from raw disk.

Key features:
- MFT entry -> data runs -> raw sectors -> file content
- ADS (Alternate Data Streams) support
- Deleted file recovery
- Large file streaming

This module completely bypasses the Windows filesystem.
Therefore, it can read locked files (pagefile.sys, registry hives, etc.).

Usage:
    from core.engine.collectors.filesystem.disk_backends import PhysicalDiskBackend
    from core.engine.collectors.filesystem.file_content_extractor import FileContentExtractor

    with PhysicalDiskBackend(0) as disk:
        extractor = FileContentExtractor(disk, partition_offset=0x100000, fs_type='NTFS')

        # Read file by MFT entry
        data = extractor.read_file_by_inode(12345)

        # Read ADS
        zone_id = extractor.read_file_by_inode(12345, stream_name="Zone.Identifier")

        # Stream large file
        for chunk in extractor.stream_file_by_inode(12345):
            process(chunk)
"""

import struct
import logging
from typing import Optional, List, Tuple, Dict, Generator, Any
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from datetime import datetime

# =============================================================================
# Debug Logging to File
# =============================================================================
_DEBUG_LOG_FILE = None

def _debug_log(message: str):
    """Output debug log to both console and file"""
    global _DEBUG_LOG_FILE
    _debug_print(message, flush=True)

    # Also write to file
    try:
        if _DEBUG_LOG_FILE is None:
            import tempfile
            log_path = Path(tempfile.gettempdir()) / "mft_collector_debug.log"
            _DEBUG_LOG_FILE = open(log_path, 'a', encoding='utf-8')

        _DEBUG_LOG_FILE.write(f"{datetime.now().isoformat()} {message}\n")
        _DEBUG_LOG_FILE.flush()
    except Exception:
        pass

from .unified_disk_reader import UnifiedDiskReader, FilesystemError

logger = logging.getLogger(__name__)

# Debug output control
_DEBUG_OUTPUT = False
def _debug_print(msg):
    if _DEBUG_OUTPUT: print(f"[FileExtractor] {msg}")


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class DataRun:
    """NTFS Data Run (cluster range)"""
    lcn: Optional[int]  # Logical Cluster Number (None = sparse)
    length: int         # Number of clusters
    vcn_start: int = 0  # Virtual Cluster Number (offset within file)

    @property
    def is_sparse(self) -> bool:
        return self.lcn is None


@dataclass
class FileMetadata:
    """File metadata (extracted from MFT entry)"""
    inode: int
    filename: str = ""
    full_path: str = ""
    size: int = 0
    allocated_size: int = 0

    is_directory: bool = False
    is_deleted: bool = False
    is_resident: bool = False

    # For resident files, data is stored within the MFT entry
    resident_data: bytes = field(default_factory=bytes)

    # Data runs for non-resident files
    data_runs: List[DataRun] = field(default_factory=list)

    # ADS (Alternate Data Streams) name list
    ads_streams: List[str] = field(default_factory=list)

    # Timestamps (FILETIME)
    created_time: int = 0
    modified_time: int = 0
    accessed_time: int = 0
    mft_changed_time: int = 0

    # Additional attributes
    parent_ref: int = 0  # Parent directory MFT reference
    flags: int = 0       # MFT entry flags


class MFTAttributeType(IntEnum):
    """NTFS MFT attribute types"""
    STANDARD_INFORMATION = 0x10
    ATTRIBUTE_LIST = 0x20
    FILE_NAME = 0x30
    OBJECT_ID = 0x40
    SECURITY_DESCRIPTOR = 0x50
    VOLUME_NAME = 0x60
    VOLUME_INFORMATION = 0x70
    DATA = 0x80
    INDEX_ROOT = 0x90
    INDEX_ALLOCATION = 0xA0
    BITMAP = 0xB0
    REPARSE_POINT = 0xC0
    EA_INFORMATION = 0xD0
    EA = 0xE0
    END_MARKER = 0xFFFFFFFF


# ==============================================================================
# File Content Extractor
# ==============================================================================

class FileContentExtractor:
    """
    Data Runs based file content extractor

    Reads file content directly from raw disk following MFT data runs.
    Completely bypasses the Windows filesystem so locked files can also be read.

    Supported filesystems:
    - NTFS (data runs)
    - FAT32/exFAT (cluster chain)
    - ext4 (extents) - partial support
    """

    # MFT Entry size (typically 1024 bytes)
    MFT_RECORD_SIZE = 1024

    # Default chunk size (64MB)
    DEFAULT_CHUNK_SIZE = 64 * 1024 * 1024

    def __init__(
        self,
        disk: UnifiedDiskReader,
        partition_offset: int,
        fs_type: str = 'NTFS'
    ):
        """
        Args:
            disk: UnifiedDiskReader backend
            partition_offset: Partition start offset (bytes)
            fs_type: Filesystem type ('NTFS', 'FAT32', 'exFAT', 'ext4')
        """
        self.disk = disk
        self.partition_offset = partition_offset
        self.fs_type = fs_type.upper()

        # Filesystem parameters (read from VBR)
        self.bytes_per_sector = 512
        self.sectors_per_cluster = 8
        self.cluster_size = 4096

        # NTFS specific
        self.mft_lcn = 0
        self.mft_record_size = 1024
        self._mft_runs: List[DataRun] = []

        # MFT preload buffer (full $MFT in memory for fast scanning)
        self._full_mft_buf: Optional[bytes] = None

        # MFT read-ahead buffer (fallback when preload is not used)
        self._mft_buf: bytes = b''
        self._mft_buf_offset: int = -1
        self._mft_readahead_entries: int = 64

        # FAT specific
        self.fat_offset = 0
        self.data_area_offset = 0
        self.root_cluster = 0

        # Initialize
        self._init_filesystem()

    def _init_filesystem(self):
        """Initialize filesystem parameters (read VBR)"""
        vbr = self.disk.read(self.partition_offset, 512)

        if self.fs_type == 'NTFS':
            self._init_ntfs(vbr)
        elif self.fs_type in ('FAT32', 'FAT16', 'FAT12', 'FAT'):
            self._init_fat(vbr)
        elif self.fs_type == 'EXFAT':
            self._init_exfat(vbr)
        elif self.fs_type in ('ext2', 'ext3', 'ext4', 'EXT2', 'EXT3', 'EXT4'):
            self._init_ext(vbr)
        elif self.fs_type in ('APFS', 'apfs'):
            self._init_apfs(vbr)
        elif self.fs_type in ('HFS+', 'HFSX', 'HFS', 'hfs+', 'hfsx', 'hfs'):
            self._init_hfs(vbr)
        else:
            logger.warning(f"Unknown filesystem type: {self.fs_type}")

    def _init_ntfs(self, vbr: bytes):
        """Initialize NTFS parameters"""
        # Check OEM ID
        if vbr[3:11] != b'NTFS    ':
            # Check for BitLocker
            if vbr[3:11] == b'-FVE-FS-':
                raise FilesystemError("BitLocker encrypted volume - cannot access raw data")
            raise FilesystemError(f"Not an NTFS partition (OEM: {vbr[3:11]})")

        # Parse BPB (BIOS Parameter Block)
        self.bytes_per_sector = struct.unpack('<H', vbr[11:13])[0]
        self.sectors_per_cluster = vbr[13]
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        # MFT location (cluster number)
        self.mft_lcn = struct.unpack('<Q', vbr[48:56])[0]

        # MFT entry size
        mft_record_size_raw = struct.unpack('<b', vbr[64:65])[0]
        if mft_record_size_raw > 0:
            self.mft_record_size = mft_record_size_raw * self.cluster_size
        else:
            self.mft_record_size = 2 ** abs(mft_record_size_raw)

        logger.info(f"[NTFS] Cluster size: {self.cluster_size}, MFT LCN: {self.mft_lcn}, "
                   f"MFT record size: {self.mft_record_size}")

        # Load MFT's own data runs (MFT entry 0)
        self._load_mft_runs()

    def _init_fat(self, vbr: bytes):
        """Initialize FAT32 parameters"""
        self.bytes_per_sector = struct.unpack('<H', vbr[11:13])[0]
        self.sectors_per_cluster = vbr[13]
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        reserved_sectors = struct.unpack('<H', vbr[14:16])[0]
        num_fats = vbr[16]
        sectors_per_fat = struct.unpack('<I', vbr[36:40])[0]

        self.root_cluster = struct.unpack('<I', vbr[44:48])[0]
        self.fat_offset = reserved_sectors * self.bytes_per_sector
        self.data_area_offset = self.fat_offset + (num_fats * sectors_per_fat * self.bytes_per_sector)

        logger.info(f"[FAT32] Cluster size: {self.cluster_size}, Root cluster: {self.root_cluster}")

    def _init_exfat(self, vbr: bytes):
        """Initialize exFAT parameters"""
        if vbr[3:11] != b'EXFAT   ':
            raise FilesystemError("Not an exFAT partition")

        # exFAT BPB
        sector_size_shift = vbr[108]
        cluster_size_shift = vbr[109]

        self.bytes_per_sector = 1 << sector_size_shift
        self.sectors_per_cluster = 1 << cluster_size_shift
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        fat_offset_sectors = struct.unpack('<I', vbr[80:84])[0]
        cluster_heap_offset = struct.unpack('<I', vbr[88:92])[0]
        self.root_cluster = struct.unpack('<I', vbr[96:100])[0]

        self.fat_offset = fat_offset_sectors * self.bytes_per_sector
        self.data_area_offset = cluster_heap_offset * self.bytes_per_sector

        logger.info(f"[exFAT] Cluster size: {self.cluster_size}, Root cluster: {self.root_cluster}")

    def _init_ext(self, vbr: bytes):
        """Initialize ext2/3/4 parameters"""
        # Superblock is at offset 1024 from partition start
        sb = self.disk.read(self.partition_offset + 1024, 256)

        # Magic number check (offset 56-57)
        magic = struct.unpack('<H', sb[56:58])[0]
        if magic != 0xEF53:
            raise FilesystemError(f"Invalid ext superblock magic: 0x{magic:04X}")

        # Filesystem parameters from superblock
        self.ext_inodes_count = struct.unpack('<I', sb[0:4])[0]
        self.ext_blocks_count = struct.unpack('<I', sb[4:8])[0]
        self.ext_first_data_block = struct.unpack('<I', sb[20:24])[0]
        self.ext_block_size_log = struct.unpack('<I', sb[24:28])[0]
        self.ext_blocks_per_group = struct.unpack('<I', sb[32:36])[0]
        self.ext_inodes_per_group = struct.unpack('<I', sb[40:44])[0]
        self.ext_inode_size = struct.unpack('<H', sb[88:90])[0] if len(sb) >= 90 else 128

        # Block size = 1024 << log_block_size
        self.cluster_size = 1024 << self.ext_block_size_log
        self.bytes_per_sector = 512
        self.sectors_per_cluster = self.cluster_size // 512

        # Feature flags for ext3/4 detection
        self.ext_compat_features = struct.unpack('<I', sb[92:96])[0] if len(sb) >= 96 else 0
        self.ext_incompat_features = struct.unpack('<I', sb[96:100])[0] if len(sb) >= 100 else 0
        self.ext_ro_compat_features = struct.unpack('<I', sb[100:104])[0] if len(sb) >= 104 else 0

        # Determine ext version
        has_extents = (self.ext_incompat_features & 0x40) != 0  # EXT4_FEATURE_INCOMPAT_EXTENTS
        has_journal = (self.ext_compat_features & 0x04) != 0   # EXT3_FEATURE_COMPAT_HAS_JOURNAL

        if has_extents:
            self.ext_version = 4
        elif has_journal:
            self.ext_version = 3
        else:
            self.ext_version = 2

        logger.info(f"[ext{self.ext_version}] Block size: {self.cluster_size}, "
                   f"Inodes: {self.ext_inodes_count}, Blocks: {self.ext_blocks_count}, "
                   f"Inode size: {self.ext_inode_size}")

    def _init_apfs(self, vbr: bytes):
        """Initialize APFS parameters"""
        # APFS Container Superblock (offset 0 or 32)
        # Check for NXSB magic
        if len(vbr) >= 36 and vbr[32:36] == b'NXSB':
            container_sb = vbr
        else:
            container_sb = self.disk.read(self.partition_offset, 4096)

        if len(container_sb) < 36 or container_sb[32:36] != b'NXSB':
            raise FilesystemError("Invalid APFS container superblock")

        # APFS uses 4096 byte blocks typically
        self.cluster_size = 4096  # Default, actual size in nx_block_size at offset 40
        if len(container_sb) >= 44:
            block_size = struct.unpack('<I', container_sb[40:44])[0]
            if block_size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
                self.cluster_size = block_size

        self.bytes_per_sector = 512
        self.sectors_per_cluster = self.cluster_size // 512

        # APFS uses pytsk3 for full support
        self.apfs_use_pytsk = True

        logger.info(f"[APFS] Block size: {self.cluster_size} (pytsk3 required for full access)")

    def _init_hfs(self, vbr: bytes):
        """Initialize HFS/HFS+ parameters"""
        # HFS+ Volume Header is at offset 1024
        vh = self.disk.read(self.partition_offset + 1024, 512)

        # Check signature (offset 0-1)
        signature = vh[0:2]
        if signature == b'H+':
            self.hfs_type = 'HFS+'
        elif signature == b'HX':
            self.hfs_type = 'HFSX'  # Case-sensitive HFS+
        elif signature == b'BD':
            self.hfs_type = 'HFS'   # Original HFS
        else:
            raise FilesystemError(f"Invalid HFS signature: {signature}")

        # HFS+ Volume Header fields
        self.hfs_version = struct.unpack('>H', vh[2:4])[0]

        # Block size (offset 40-43, big-endian)
        self.cluster_size = struct.unpack('>I', vh[40:44])[0]
        self.bytes_per_sector = 512
        self.sectors_per_cluster = self.cluster_size // 512

        # Total blocks (offset 44-47)
        self.hfs_total_blocks = struct.unpack('>I', vh[44:48])[0]

        # Free blocks (offset 48-51)
        self.hfs_free_blocks = struct.unpack('>I', vh[48:52])[0]

        # HFS uses pytsk3 for full support
        self.hfs_use_pytsk = True

        logger.info(f"[{self.hfs_type}] Block size: {self.cluster_size}, "
                   f"Total blocks: {self.hfs_total_blocks} (pytsk3 required for full access)")

    # ==========================================================================
    # ext2/3/4 Operations
    # ==========================================================================

    def _get_ext_block_group_descriptor(self, group_num: int) -> dict:
        """Read ext block group descriptor"""
        # Block group descriptor table starts at block 1 (or 2 for 1K block size)
        if self.cluster_size == 1024:
            gdt_block = 2
        else:
            gdt_block = 1

        gdt_offset = self.partition_offset + (gdt_block * self.cluster_size)
        desc_size = 32 if not (self.ext_incompat_features & 0x80) else 64  # 64-byte for ext4

        desc_data = self.disk.read(gdt_offset + (group_num * desc_size), desc_size)

        return {
            'block_bitmap': struct.unpack('<I', desc_data[0:4])[0],
            'inode_bitmap': struct.unpack('<I', desc_data[4:8])[0],
            'inode_table': struct.unpack('<I', desc_data[8:12])[0],
            'free_blocks': struct.unpack('<H', desc_data[12:14])[0],
            'free_inodes': struct.unpack('<H', desc_data[14:16])[0],
            'used_dirs': struct.unpack('<H', desc_data[16:18])[0],
        }

    def _read_ext_inode(self, inode_num: int) -> bytes:
        """Read ext inode"""
        if inode_num < 1:
            raise FilesystemError(f"Invalid inode number: {inode_num}")

        # Inode numbers start at 1
        inode_index = inode_num - 1

        # Calculate block group
        group_num = inode_index // self.ext_inodes_per_group
        local_index = inode_index % self.ext_inodes_per_group

        # Get block group descriptor
        bgd = self._get_ext_block_group_descriptor(group_num)

        # Calculate inode offset
        inode_table_block = bgd['inode_table']
        inode_offset = self.partition_offset + (inode_table_block * self.cluster_size)
        inode_offset += local_index * self.ext_inode_size

        return self.disk.read(inode_offset, self.ext_inode_size)

    def _parse_ext_inode(self, inode_data: bytes) -> dict:
        """Parse ext inode"""
        return {
            'mode': struct.unpack('<H', inode_data[0:2])[0],
            'uid': struct.unpack('<H', inode_data[2:4])[0],
            'size': struct.unpack('<I', inode_data[4:8])[0],
            'atime': struct.unpack('<I', inode_data[8:12])[0],
            'ctime': struct.unpack('<I', inode_data[12:16])[0],
            'mtime': struct.unpack('<I', inode_data[16:20])[0],
            'dtime': struct.unpack('<I', inode_data[20:24])[0],
            'gid': struct.unpack('<H', inode_data[24:26])[0],
            'links_count': struct.unpack('<H', inode_data[26:28])[0],
            'blocks': struct.unpack('<I', inode_data[28:32])[0],
            'flags': struct.unpack('<I', inode_data[32:36])[0],
            'block_pointers': inode_data[40:100],  # 15 * 4 bytes
            'size_high': struct.unpack('<I', inode_data[108:112])[0] if len(inode_data) >= 112 else 0,
        }

    def _read_ext_file_blocks(self, inode_data: bytes, file_size: int) -> bytes:
        """Read ext file blocks (direct/indirect blocks)"""
        inode = self._parse_ext_inode(inode_data)

        # Check for extents (ext4)
        uses_extents = (inode['flags'] & 0x80000) != 0  # EXT4_EXTENTS_FL

        if uses_extents:
            return self._read_ext4_extents(inode_data, file_size)
        else:
            return self._read_ext_indirect_blocks(inode_data, file_size)

    def _read_ext4_extents(self, inode_data: bytes, file_size: int) -> bytes:
        """Read file data from ext4 extent tree"""
        data = bytearray()
        bytes_read = 0

        # Extent header is at offset 40 in inode
        extent_data = inode_data[40:100]  # 60 bytes for extent tree root

        # Parse extent header
        eh_magic = struct.unpack('<H', extent_data[0:2])[0]
        if eh_magic != 0xF30A:
            # Fallback to indirect blocks
            return self._read_ext_indirect_blocks(inode_data, file_size)

        eh_entries = struct.unpack('<H', extent_data[2:4])[0]
        eh_depth = struct.unpack('<H', extent_data[6:8])[0]

        if eh_depth == 0:
            # Leaf node - read extents directly
            for i in range(eh_entries):
                extent_offset = 12 + (i * 12)  # Each extent is 12 bytes
                if extent_offset + 12 > len(extent_data):
                    break

                ext_block = extent_data[extent_offset:extent_offset + 12]
                ee_block = struct.unpack('<I', ext_block[0:4])[0]  # Logical block
                ee_len = struct.unpack('<H', ext_block[4:6])[0]    # Length
                ee_start_hi = struct.unpack('<H', ext_block[6:8])[0]
                ee_start_lo = struct.unpack('<I', ext_block[8:12])[0]
                ee_start = (ee_start_hi << 32) | ee_start_lo

                # Handle uninitialized extent (bit 15 set)
                if ee_len > 32768:
                    ee_len -= 32768
                    # Uninitialized - return zeros
                    sparse_size = min(ee_len * self.cluster_size, file_size - bytes_read)
                    data.extend(b'\x00' * sparse_size)
                    bytes_read += sparse_size
                else:
                    # Read extent data
                    for block_num in range(ee_len):
                        if bytes_read >= file_size:
                            break
                        block_offset = self.partition_offset + ((ee_start + block_num) * self.cluster_size)
                        read_size = min(self.cluster_size, file_size - bytes_read)
                        block_data = self.disk.read(block_offset, read_size)
                        data.extend(block_data)
                        bytes_read += len(block_data)
        else:
            # Internal node - need to read child nodes
            # For simplicity, we'll use a recursive approach for deep trees
            logger.warning(f"Deep extent tree (depth={eh_depth}) - simplified reading")
            # Fallback to reading sequentially
            return self._read_ext_indirect_blocks(inode_data, file_size)

        return bytes(data[:file_size])

    def _read_ext_indirect_blocks(self, inode_data: bytes, file_size: int) -> bytes:
        """Read file using ext2/3 indirect block method"""
        data = bytearray()
        bytes_read = 0

        # Block pointers at offset 40 (15 * 4 = 60 bytes)
        block_ptrs = inode_data[40:100]

        # Direct blocks (0-11)
        for i in range(12):
            if bytes_read >= file_size:
                break
            block_num = struct.unpack('<I', block_ptrs[i*4:(i+1)*4])[0]
            if block_num == 0:
                continue
            block_offset = self.partition_offset + (block_num * self.cluster_size)
            read_size = min(self.cluster_size, file_size - bytes_read)
            block_data = self.disk.read(block_offset, read_size)
            data.extend(block_data)
            bytes_read += len(block_data)

        if bytes_read >= file_size:
            return bytes(data[:file_size])

        # Indirect block (12)
        indirect_block = struct.unpack('<I', block_ptrs[48:52])[0]
        if indirect_block != 0:
            bytes_read = self._read_indirect_block(indirect_block, data, bytes_read, file_size, 1)

        if bytes_read >= file_size:
            return bytes(data[:file_size])

        # Double indirect block (13)
        dindirect_block = struct.unpack('<I', block_ptrs[52:56])[0]
        if dindirect_block != 0:
            bytes_read = self._read_indirect_block(dindirect_block, data, bytes_read, file_size, 2)

        if bytes_read >= file_size:
            return bytes(data[:file_size])

        # Triple indirect block (14)
        tindirect_block = struct.unpack('<I', block_ptrs[56:60])[0]
        if tindirect_block != 0:
            bytes_read = self._read_indirect_block(tindirect_block, data, bytes_read, file_size, 3)

        return bytes(data[:file_size])

    def _read_indirect_block(self, block_num: int, data: bytearray, bytes_read: int,
                             file_size: int, level: int) -> int:
        """Recursively read indirect blocks"""
        if bytes_read >= file_size or block_num == 0:
            return bytes_read

        # Read the indirect block
        block_offset = self.partition_offset + (block_num * self.cluster_size)
        indirect_data = self.disk.read(block_offset, self.cluster_size)

        # Number of pointers per block
        ptrs_per_block = self.cluster_size // 4

        for i in range(ptrs_per_block):
            if bytes_read >= file_size:
                break

            ptr = struct.unpack('<I', indirect_data[i*4:(i+1)*4])[0]
            if ptr == 0:
                continue

            if level == 1:
                # Direct data block
                data_offset = self.partition_offset + (ptr * self.cluster_size)
                read_size = min(self.cluster_size, file_size - bytes_read)
                block_data = self.disk.read(data_offset, read_size)
                data.extend(block_data)
                bytes_read += len(block_data)
            else:
                # Recurse to lower level
                bytes_read = self._read_indirect_block(ptr, data, bytes_read, file_size, level - 1)

        return bytes_read

    # ==========================================================================
    # MFT Operations
    # ==========================================================================

    def _load_mft_runs(self):
        """Load MFT's own data runs (entry 0)"""
        # Read MFT entry 0 (MFT itself)
        mft_offset = self.partition_offset + (self.mft_lcn * self.cluster_size)
        entry_0 = self.disk.read(mft_offset, self.mft_record_size)

        if entry_0[:4] != b'FILE':
            raise FilesystemError("Invalid MFT entry 0 signature")

        # Apply fixup
        entry_0 = self._apply_fixup(entry_0)

        # Parse data runs from $DATA attribute
        self._mft_runs = self._parse_data_attribute(entry_0)

        if not self._mft_runs:
            # Fallback: assume contiguous MFT
            logger.warning("Could not parse MFT data runs, assuming contiguous MFT")
            self._mft_runs = [DataRun(lcn=self.mft_lcn, length=1000000, vcn_start=0)]

        logger.debug(f"MFT data runs: {len(self._mft_runs)}")

    def _apply_fixup(self, entry: bytes) -> bytes:
        """Apply MFT entry's fixup array"""
        if len(entry) < 48:
            return entry

        # Update Sequence Array offset and count
        usa_offset = struct.unpack('<H', entry[4:6])[0]
        usa_count = struct.unpack('<H', entry[6:8])[0]

        if usa_offset == 0 or usa_count < 2:
            return entry

        entry = bytearray(entry)

        # Read USA value
        usa_value = entry[usa_offset:usa_offset + 2]

        # Apply USA to end of each sector
        for i in range(1, usa_count):
            sector_end = (i * 512) - 2
            if sector_end + 2 <= len(entry) and usa_offset + (i * 2) + 2 <= len(entry):
                # Validate and restore USA
                original_bytes = entry[usa_offset + (i * 2):usa_offset + (i * 2) + 2]
                entry[sector_end:sector_end + 2] = original_bytes

        return bytes(entry)

    # ==========================================================================
    # MFT Preload — read entire $MFT into memory for bulk scanning
    # ==========================================================================

    _MFT_PRELOAD_MAX_SIZE = 512 * 1024 * 1024   # 512MB limit
    _MFT_PRELOAD_CHUNK_SIZE = 4 * 1024 * 1024   # 4MB per I/O

    def preload_mft(self) -> bool:
        """Read entire $MFT into memory for fast sequential scanning.

        Converts hundreds of thousands of per-entry I/O operations into
        a handful of large sequential reads. Critical for BitLocker
        decrypted volumes where each I/O incurs overhead.

        Returns True if preloaded successfully.
        """
        if self._full_mft_buf is not None:
            return True

        # Estimate total size
        total_size = sum(run.length * self.cluster_size for run in self._mft_runs)

        if total_size > self._MFT_PRELOAD_MAX_SIZE:
            logger.info(
                f"MFT too large for preload ({total_size / (1024**2):.0f}MB "
                f"> {self._MFT_PRELOAD_MAX_SIZE / (1024**2):.0f}MB), "
                f"using readahead buffer"
            )
            return False

        try:
            chunks = []
            bytes_read = 0

            for run in self._mft_runs:
                run_bytes = run.length * self.cluster_size

                if run.is_sparse:
                    chunks.append(b'\x00' * run_bytes)
                    bytes_read += run_bytes
                    continue

                run_start = self.partition_offset + (run.lcn * self.cluster_size)
                offset = 0

                while offset < run_bytes:
                    chunk_size = min(self._MFT_PRELOAD_CHUNK_SIZE, run_bytes - offset)
                    data = self.disk.read(run_start + offset, chunk_size)
                    chunks.append(data)
                    offset += len(data)
                    bytes_read += len(data)

            self._full_mft_buf = b''.join(chunks)
            logger.info(f"MFT preloaded: {len(self._full_mft_buf) / (1024**2):.1f} MB")
            return True

        except Exception as e:
            logger.warning(f"MFT preload failed, falling back to per-entry read: {e}")
            self._full_mft_buf = None
            return False

    def release_mft_preload(self) -> None:
        """Release preloaded MFT data to free memory."""
        if self._full_mft_buf is not None:
            size_mb = len(self._full_mft_buf) / (1024**2)
            self._full_mft_buf = None
            self._mft_buf = b''
            self._mft_buf_offset = -1
            logger.info(f"MFT preload released ({size_mb:.1f} MB freed)")

    def read_mft_entry(self, entry_number: int) -> bytes:
        """
        Read MFT entry (supports fragmented MFT)

        Fast path: if MFT is preloaded, slices directly from memory buffer.
        Fallback: uses read-ahead buffer for sequential scan performance.

        Args:
            entry_number: MFT entry number

        Returns:
            MFT entry data (fixup applied)
        """
        # Fast path: preloaded MFT — simple array slice, no I/O
        if self._full_mft_buf is not None:
            offset = entry_number * self.mft_record_size
            end = offset + self.mft_record_size
            if end <= len(self._full_mft_buf):
                entry_data = self._full_mft_buf[offset:end]
                if entry_data[:4] == b'FILE':
                    entry_data = self._apply_fixup(entry_data)
                return entry_data

        # Slow path: per-entry read with readahead buffer
        entries_per_cluster = self.cluster_size // self.mft_record_size
        target_entry = entry_number

        # Find entry position following data runs
        for run in self._mft_runs:
            if run.is_sparse:
                continue

            entries_in_run = run.length * entries_per_cluster

            if target_entry < entries_in_run:
                cluster_offset = target_entry // entries_per_cluster
                entry_in_cluster = target_entry % entries_per_cluster

                disk_offset = self.partition_offset + ((run.lcn + cluster_offset) * self.cluster_size)
                disk_offset += entry_in_cluster * self.mft_record_size

                # Check read-ahead buffer
                if (self._mft_buf_offset >= 0 and
                        disk_offset >= self._mft_buf_offset and
                        disk_offset + self.mft_record_size <= self._mft_buf_offset + len(self._mft_buf)):
                    buf_pos = disk_offset - self._mft_buf_offset
                    entry_data = self._mft_buf[buf_pos:buf_pos + self.mft_record_size]
                else:
                    # Read ahead: multiple entries at once within this run
                    remaining_in_run = entries_in_run - target_entry
                    readahead_count = min(remaining_in_run, self._mft_readahead_entries)
                    readahead_bytes = readahead_count * self.mft_record_size

                    self._mft_buf = self.disk.read(disk_offset, readahead_bytes)
                    self._mft_buf_offset = disk_offset
                    entry_data = self._mft_buf[:self.mft_record_size]

                # Apply fixup
                if entry_data[:4] == b'FILE':
                    entry_data = self._apply_fixup(entry_data)

                return entry_data

            target_entry -= entries_in_run

        raise FilesystemError(f"MFT entry {entry_number} not found in data runs")

    def _parse_data_attribute(
        self,
        mft_entry: bytes,
        stream_name: str = None
    ) -> List[DataRun]:
        """
        Parse data runs from $DATA attribute in MFT entry

        Args:
            mft_entry: MFT entry data
            stream_name: ADS name (None = default $DATA)

        Returns:
            List of DataRun
        """
        if mft_entry[:4] != b'FILE':
            return []

        runs = []
        attr_offset = struct.unpack('<H', mft_entry[0x14:0x16])[0]
        pos = attr_offset

        while pos < len(mft_entry) - 24:
            attr_type = struct.unpack('<I', mft_entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', mft_entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            # $DATA attribute (0x80)
            if attr_type == MFTAttributeType.DATA:
                # Check attribute name
                name_length = mft_entry[pos+9]
                attr_name = ""

                if name_length > 0:
                    name_offset = struct.unpack('<H', mft_entry[pos+10:pos+12])[0]
                    attr_name = mft_entry[pos+name_offset:pos+name_offset+name_length*2].decode('utf-16-le', errors='ignore')

                # Stream name matching
                if stream_name is not None:
                    if attr_name != stream_name:
                        pos += attr_length
                        continue
                elif name_length > 0:
                    # Looking for default $DATA (no name) - skip named streams
                    pos += attr_length
                    continue

                # Non-resident flag
                non_resident = mft_entry[pos+8]

                if non_resident:
                    runs = self._parse_data_runs_bytes(mft_entry, pos)
                    if runs:
                        return runs

            pos += attr_length

        return runs

    def _parse_data_runs_bytes(self, mft_entry: bytes, attr_pos: int) -> List[DataRun]:
        """Parse data runs bytes"""
        runs = []

        data_runs_offset = struct.unpack('<H', mft_entry[attr_pos+0x20:attr_pos+0x22])[0]
        pos = attr_pos + data_runs_offset
        current_lcn = 0
        vcn = 0

        while pos < len(mft_entry) - 1:
            header = mft_entry[pos]

            if header == 0:
                break

            length_bytes = header & 0x0F
            offset_bytes = (header >> 4) & 0x0F

            if length_bytes == 0:
                break

            if pos + 1 + length_bytes > len(mft_entry):
                break

            # Run length (cluster count)
            run_length = int.from_bytes(
                mft_entry[pos+1:pos+1+length_bytes],
                byteorder='little'
            )

            # Run offset (relative LCN)
            is_sparse = False
            if offset_bytes > 0:
                if pos + 1 + length_bytes + offset_bytes > len(mft_entry):
                    break

                run_offset = int.from_bytes(
                    mft_entry[pos+1+length_bytes:pos+1+length_bytes+offset_bytes],
                    byteorder='little',
                    signed=True
                )
                current_lcn += run_offset
            else:
                # Sparse run
                is_sparse = True

            runs.append(DataRun(
                lcn=None if is_sparse else current_lcn,
                length=run_length,
                vcn_start=vcn
            ))

            vcn += run_length
            pos += 1 + length_bytes + offset_bytes

        return runs

    # ==========================================================================
    # File Content Reading
    # ==========================================================================

    def read_file_by_inode(
        self,
        inode: int,
        stream_name: str = None,
        max_size: int = None
    ) -> bytes:
        """
        Read file content by MFT entry number

        Args:
            inode: MFT entry number
            stream_name: ADS name (None = default $DATA)
            max_size: Maximum read size

        Returns:
            File content (bytes)
        """
        # Read MFT entry
        entry = self.read_mft_entry(inode)

        if entry[:4] != b'FILE':
            raise FilesystemError(f"Invalid MFT entry at inode {inode}")

        # Extract file metadata
        metadata = self._parse_mft_entry_metadata(entry, inode, stream_name)

        # Resident data
        if metadata.is_resident:
            data = metadata.resident_data
            if max_size:
                data = data[:max_size]
            return data

        # Non-resident: read following data runs
        return self._read_data_runs(metadata.data_runs, metadata.size, max_size)

    def stream_file_by_inode(
        self,
        inode: int,
        stream_name: str = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE
    ) -> Generator[bytes, None, None]:
        """
        Stream large file

        Args:
            inode: MFT entry number
            stream_name: ADS name
            chunk_size: Chunk size

        Yields:
            File data chunks
        """
        entry = self.read_mft_entry(inode)
        metadata = self._parse_mft_entry_metadata(entry, inode, stream_name)

        if metadata.is_resident:
            yield metadata.resident_data
            return

        yield from self._stream_data_runs(metadata.data_runs, metadata.size, chunk_size)

    def get_file_metadata(self, inode: int, entry_data: bytes = None) -> FileMetadata:
        """
        Get file metadata

        Args:
            inode: MFT entry number
            entry_data: Pre-read MFT entry bytes (skips re-read if provided)

        Returns:
            FileMetadata object
        """
        if entry_data is None:
            entry_data = self.read_mft_entry(inode)
        return self._parse_mft_entry_metadata(entry_data, inode)

    def list_ads_streams(self, inode: int) -> List[str]:
        """
        List ADS streams

        Args:
            inode: MFT entry number

        Returns:
            List of ADS names (excluding default $DATA)
        """
        entry = self.read_mft_entry(inode)
        return self._extract_ads_list(entry)

    # ==========================================================================
    # Internal Methods
    # ==========================================================================

    def _parse_mft_entry_metadata(
        self,
        entry: bytes,
        inode: int,
        stream_name: str = None
    ) -> FileMetadata:
        """Extract metadata from MFT entry"""
        if entry[:4] != b'FILE':
            raise FilesystemError(f"Invalid MFT signature at inode {inode}")

        # Flags
        flags = struct.unpack('<H', entry[0x16:0x18])[0]
        is_directory = (flags & 0x02) != 0
        is_deleted = (flags & 0x01) == 0

        # Extract filename
        filename = self._extract_filename(entry)

        # Extract timestamps
        timestamps = self._extract_timestamps(entry)

        # Parent directory reference
        parent_ref = self._extract_parent_ref(entry)

        # ADS list
        ads_streams = self._extract_ads_list(entry)

        # Parse $DATA attribute
        is_resident, resident_data, data_runs, file_size = self._extract_data_info(entry, stream_name)

        return FileMetadata(
            inode=inode,
            filename=filename,
            size=file_size,
            is_directory=is_directory,
            is_deleted=is_deleted,
            is_resident=is_resident,
            resident_data=resident_data,
            data_runs=data_runs,
            ads_streams=ads_streams,
            created_time=timestamps.get('created', 0),
            modified_time=timestamps.get('modified', 0),
            accessed_time=timestamps.get('accessed', 0),
            mft_changed_time=timestamps.get('mft_changed', 0),
            parent_ref=parent_ref,
            flags=flags
        )

    def _extract_filename(self, entry: bytes) -> str:
        """Extract filename from $FILE_NAME attribute"""
        attr_offset = struct.unpack('<H', entry[0x14:0x16])[0]
        pos = attr_offset

        filename = ""

        while pos < len(entry) - 24:
            attr_type = struct.unpack('<I', entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            # $FILE_NAME attribute (0x30)
            if attr_type == MFTAttributeType.FILE_NAME:
                non_resident = entry[pos+8]

                if not non_resident:  # FILE_NAME is always resident
                    content_offset = struct.unpack('<H', entry[pos+0x14:pos+0x16])[0]
                    content_pos = pos + content_offset

                    if content_pos + 66 <= len(entry):
                        # Filename length (character count)
                        name_length = entry[content_pos + 64]
                        namespace = entry[content_pos + 65]

                        # Prefer Win32 or POSIX namespace
                        if namespace in (1, 3) or not filename:  # Win32, POSIX
                            name_bytes = entry[content_pos + 66:content_pos + 66 + name_length * 2]
                            try:
                                new_filename = name_bytes.decode('utf-16-le')
                                if namespace in (1, 3) or not filename:
                                    filename = new_filename
                            except (UnicodeDecodeError, ValueError):
                                pass

            pos += attr_length

        return filename

    def _extract_timestamps(self, entry: bytes) -> Dict[str, int]:
        """Extract timestamps from $STANDARD_INFORMATION"""
        timestamps = {}

        attr_offset = struct.unpack('<H', entry[0x14:0x16])[0]
        pos = attr_offset

        while pos < len(entry) - 24:
            attr_type = struct.unpack('<I', entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            # $STANDARD_INFORMATION (0x10)
            if attr_type == MFTAttributeType.STANDARD_INFORMATION:
                non_resident = entry[pos+8]

                if not non_resident:
                    content_offset = struct.unpack('<H', entry[pos+0x14:pos+0x16])[0]
                    content_pos = pos + content_offset

                    if content_pos + 32 <= len(entry):
                        timestamps['created'] = struct.unpack('<Q', entry[content_pos:content_pos+8])[0]
                        timestamps['modified'] = struct.unpack('<Q', entry[content_pos+8:content_pos+16])[0]
                        timestamps['mft_changed'] = struct.unpack('<Q', entry[content_pos+16:content_pos+24])[0]
                        timestamps['accessed'] = struct.unpack('<Q', entry[content_pos+24:content_pos+32])[0]

                    return timestamps

            pos += attr_length

        return timestamps

    def _extract_parent_ref(self, entry: bytes) -> int:
        """Extract parent directory reference from $FILE_NAME"""
        attr_offset = struct.unpack('<H', entry[0x14:0x16])[0]
        pos = attr_offset

        while pos < len(entry) - 24:
            attr_type = struct.unpack('<I', entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            if attr_type == MFTAttributeType.FILE_NAME:
                non_resident = entry[pos+8]

                if not non_resident:
                    content_offset = struct.unpack('<H', entry[pos+0x14:pos+0x16])[0]
                    content_pos = pos + content_offset

                    if content_pos + 8 <= len(entry):
                        parent_ref = struct.unpack('<Q', entry[content_pos:content_pos+8])[0]
                        return parent_ref & 0xFFFFFFFFFFFF  # Lower 48 bits only

            pos += attr_length

        return 0

    def _parse_attribute_list(self, entry: bytes) -> List[Dict[str, Any]]:
        """
        Parse ATTRIBUTE_LIST attribute - extract extension MFT record references

        Returns:
            List of dicts with keys:
            - attr_type: Attribute type (0x80 = $DATA)
            - name: Attribute name (ADS stream name)
            - mft_ref: Extension MFT record number
            - starting_vcn: Starting VCN
        """
        result = []

        attr_offset = struct.unpack('<H', entry[0x14:0x16])[0]
        pos = attr_offset

        while pos < len(entry) - 24:
            attr_type = struct.unpack('<I', entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            # ATTRIBUTE_LIST attribute (0x20)
            if attr_type == MFTAttributeType.ATTRIBUTE_LIST:
                non_resident = entry[pos+8]

                if non_resident:
                    # Non-resident ATTRIBUTE_LIST - need to follow data runs
                    # Complex case, currently skipped
                    logger.debug("Non-resident ATTRIBUTE_LIST - not supported yet")
                else:
                    # Resident ATTRIBUTE_LIST
                    content_length = struct.unpack('<I', entry[pos+0x10:pos+0x14])[0]
                    content_offset = struct.unpack('<H', entry[pos+0x14:pos+0x16])[0]
                    list_data = entry[pos+content_offset:pos+content_offset+content_length]

                    # Parse ATTRIBUTE_LIST entries
                    list_pos = 0
                    while list_pos < len(list_data) - 26:
                        entry_type = struct.unpack('<I', list_data[list_pos:list_pos+4])[0]
                        entry_length = struct.unpack('<H', list_data[list_pos+4:list_pos+6])[0]

                        if entry_length == 0 or entry_length < 26:
                            break

                        name_length = list_data[list_pos+6]
                        name_offset = list_data[list_pos+7]
                        starting_vcn = struct.unpack('<Q', list_data[list_pos+8:list_pos+16])[0]
                        mft_ref = struct.unpack('<Q', list_data[list_pos+16:list_pos+24])[0]
                        mft_record_num = mft_ref & 0xFFFFFFFFFFFF  # Lower 48 bits

                        # Extract attribute name
                        attr_name = ""
                        if name_length > 0:
                            name_start = list_pos + name_offset
                            name_end = name_start + name_length * 2
                            if name_end <= len(list_data):
                                attr_name = list_data[name_start:name_end].decode('utf-16-le', errors='ignore')

                        result.append({
                            'attr_type': entry_type,
                            'name': attr_name,
                            'mft_ref': mft_record_num,
                            'starting_vcn': starting_vcn
                        })

                        list_pos += entry_length

                return result

            pos += attr_length

        return result

    def _extract_data_info(
        self,
        entry: bytes,
        stream_name: str = None
    ) -> Tuple[bool, bytes, List[DataRun], int]:
        """Extract data info from $DATA attribute (ATTRIBUTE_LIST supported)"""
        attr_offset = struct.unpack('<H', entry[0x14:0x16])[0]
        pos = attr_offset

        # First search for $DATA attribute in base MFT entry
        while pos < len(entry) - 24:
            attr_type = struct.unpack('<I', entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            if attr_type == MFTAttributeType.DATA:
                # Check stream name
                name_length = entry[pos+9]
                attr_name = ""

                if name_length > 0:
                    name_offset = struct.unpack('<H', entry[pos+10:pos+12])[0]
                    attr_name = entry[pos+name_offset:pos+name_offset+name_length*2].decode('utf-16-le', errors='ignore')

                # Name matching
                if stream_name is not None:
                    if attr_name != stream_name:
                        pos += attr_length
                        continue
                elif name_length > 0:
                    pos += attr_length
                    continue

                non_resident = entry[pos+8]

                if non_resident:
                    # Non-resident
                    real_size = struct.unpack('<Q', entry[pos+0x30:pos+0x38])[0]
                    data_runs = self._parse_data_runs_bytes(entry, pos)
                    return False, b'', data_runs, real_size
                else:
                    # Resident
                    content_length = struct.unpack('<I', entry[pos+0x10:pos+0x14])[0]
                    content_offset = struct.unpack('<H', entry[pos+0x14:pos+0x16])[0]
                    content_pos = pos + content_offset

                    if content_pos + content_length <= len(entry):
                        resident_data = entry[content_pos:content_pos+content_length]
                        return True, resident_data, [], content_length

            pos += attr_length

        # If not found in base entry, check ATTRIBUTE_LIST
        attr_list = self._parse_attribute_list(entry)

        if attr_list and stream_name:
            # Find extension record containing the target stream's $DATA attribute
            target_refs = []
            for attr_info in attr_list:
                if attr_info['attr_type'] == MFTAttributeType.DATA:
                    if attr_info['name'] == stream_name:
                        target_refs.append(attr_info)

            if target_refs:
                # Sort by VCN order
                target_refs.sort(key=lambda x: x['starting_vcn'])

                # Collect data runs from all extension records
                all_data_runs = []
                total_size = 0

                for ref_info in target_refs:
                    try:
                        ext_entry = self.read_mft_entry(ref_info['mft_ref'])
                        if ext_entry[:4] != b'FILE':
                            continue

                        # Parse $DATA attribute from extension entry
                        ext_result = self._extract_data_from_extension(ext_entry, stream_name)
                        if ext_result:
                            is_res, res_data, runs, size = ext_result
                            if runs:
                                all_data_runs.extend(runs)
                            if size > total_size:
                                total_size = size
                    except Exception as e:
                        continue

                if all_data_runs:
                    return False, b'', all_data_runs, total_size

        return True, b'', [], 0

    def _extract_data_from_extension(
        self,
        ext_entry: bytes,
        stream_name: str
    ) -> Optional[Tuple[bool, bytes, List[DataRun], int]]:
        """Extract specific stream's $DATA attribute from extension MFT entry"""
        attr_offset = struct.unpack('<H', ext_entry[0x14:0x16])[0]
        pos = attr_offset

        while pos < len(ext_entry) - 24:
            attr_type = struct.unpack('<I', ext_entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', ext_entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            if attr_type == MFTAttributeType.DATA:
                name_length = ext_entry[pos+9]
                attr_name = ""

                if name_length > 0:
                    name_offset = struct.unpack('<H', ext_entry[pos+10:pos+12])[0]
                    attr_name = ext_entry[pos+name_offset:pos+name_offset+name_length*2].decode('utf-16-le', errors='ignore')

                if attr_name == stream_name:
                    non_resident = ext_entry[pos+8]

                    if non_resident:
                        real_size = struct.unpack('<Q', ext_entry[pos+0x30:pos+0x38])[0]
                        data_runs = self._parse_data_runs_bytes(ext_entry, pos)
                        return False, b'', data_runs, real_size
                    else:
                        content_length = struct.unpack('<I', ext_entry[pos+0x10:pos+0x14])[0]
                        content_offset = struct.unpack('<H', ext_entry[pos+0x14:pos+0x16])[0]
                        content_pos = pos + content_offset

                        if content_pos + content_length <= len(ext_entry):
                            resident_data = ext_entry[content_pos:content_pos+content_length]
                            return True, resident_data, [], content_length

            pos += attr_length

        return None

    def _extract_ads_list(self, entry: bytes) -> List[str]:
        """Extract ADS stream name list"""
        ads_names = []

        attr_offset = struct.unpack('<H', entry[0x14:0x16])[0]
        pos = attr_offset

        while pos < len(entry) - 24:
            attr_type = struct.unpack('<I', entry[pos:pos+4])[0]

            if attr_type == MFTAttributeType.END_MARKER:
                break

            attr_length = struct.unpack('<I', entry[pos+4:pos+8])[0]
            if attr_length == 0 or attr_length > self.mft_record_size:
                break

            if attr_type == MFTAttributeType.DATA:
                name_length = entry[pos+9]

                if name_length > 0:
                    name_offset = struct.unpack('<H', entry[pos+10:pos+12])[0]
                    try:
                        name = entry[pos+name_offset:pos+name_offset+name_length*2].decode('utf-16-le')
                        if name not in ads_names:
                            ads_names.append(name)
                    except (UnicodeDecodeError, ValueError):
                        pass

            pos += attr_length

        return ads_names

    def _read_data_runs(
        self,
        data_runs: List[DataRun],
        file_size: int,
        max_size: int = None
    ) -> bytes:
        """Read file data following data runs"""
        if max_size is not None:
            target_size = min(file_size, max_size)
        else:
            target_size = file_size

        data = bytearray()
        bytes_read = 0

        for run in data_runs:
            if bytes_read >= target_size:
                break

            if run.is_sparse:
                # Sparse run - fill with zeros
                sparse_size = min(run.length * self.cluster_size, target_size - bytes_read)
                data.extend(b'\x00' * sparse_size)
                bytes_read += sparse_size
            else:
                # Read actual clusters
                run_offset = self.partition_offset + (run.lcn * self.cluster_size)
                run_size = min(run.length * self.cluster_size, target_size - bytes_read)

                chunk = self.disk.read(run_offset, run_size)
                data.extend(chunk)
                bytes_read += len(chunk)

        return bytes(data[:target_size])

    def _stream_data_runs(
        self,
        data_runs: List[DataRun],
        file_size: int,
        chunk_size: int
    ) -> Generator[bytes, None, None]:
        """Stream file data following data runs"""
        import time

        bytes_read = 0
        run_index = 0
        total_runs = len(data_runs)
        start_time = time.time()

        # Debug: file size limit (prevent infinite loop from corrupted MFT)
        MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB
        if file_size > MAX_FILE_SIZE:
            _debug_log(f"[SANITY CHECK] Abnormally large file_size: {file_size / 1024 / 1024 / 1024:.2f}GB - limiting to 10GB")
            file_size = MAX_FILE_SIZE

        for run in data_runs:
            if bytes_read >= file_size:
                break

            run_index += 1

            if run.is_sparse:
                # Sparse run
                sparse_remaining = run.length * self.cluster_size

                # Debug: sparse run warning
                if sparse_remaining > 1024 * 1024 * 1024:  # 1GB or more
                    _debug_log(f"[SPARSE] Large sparse run: {sparse_remaining / 1024 / 1024:.1f}MB")

                while sparse_remaining > 0 and bytes_read < file_size:
                    yield_size = min(chunk_size, sparse_remaining, file_size - bytes_read)
                    yield b'\x00' * yield_size
                    sparse_remaining -= yield_size
                    bytes_read += yield_size
            else:
                # Actual clusters
                run_offset = self.partition_offset + (run.lcn * self.cluster_size)
                run_size = run.length * self.cluster_size
                run_read = 0

                # Debug: offset validation
                if run_offset < 0 or run.lcn < 0:
                    _debug_log(f"[INVALID] Negative offset: lcn={run.lcn}, offset={run_offset}")
                    continue

                while run_read < run_size and bytes_read < file_size:
                    read_size = min(chunk_size, run_size - run_read, file_size - bytes_read)

                    # Debug: measure time before read
                    read_start = time.time()
                    chunk = self.disk.read(run_offset + run_read, read_size)
                    read_elapsed = time.time() - read_start

                    # Slow read warning (1 second or more)
                    if read_elapsed > 1.0:
                        _debug_log(f"[SLOW READ] {read_elapsed:.2f}s for {read_size} bytes at offset {run_offset + run_read}")

                    if not chunk:
                        _debug_log(f"[EMPTY CHUNK] run {run_index}/{total_runs}, offset={run_offset + run_read}")
                        break

                    yield chunk
                    run_read += len(chunk)
                    bytes_read += len(chunk)

                    # Timeout check (single file max 10 minutes)
                    if time.time() - start_time > 600:
                        _debug_log(f"[STREAM TIMEOUT] 10min limit reached at {bytes_read / 1024 / 1024:.1f}MB")
                        return

    # ==========================================================================
    # FAT Support
    # ==========================================================================

    def get_fat_cluster_chain(self, start_cluster: int) -> List[int]:
        """Read FAT cluster chain"""
        chain = []
        cluster = start_cluster
        visited = set()

        while cluster >= 2 and cluster < 0x0FFFFFF8:
            if cluster in visited:
                logger.warning(f"Circular reference in FAT chain at cluster {cluster}")
                break
            visited.add(cluster)
            chain.append(cluster)

            # Read next cluster from FAT table
            fat_entry_offset = self.partition_offset + self.fat_offset + (cluster * 4)
            entry_data = self.disk.read(fat_entry_offset, 4)
            cluster = struct.unpack('<I', entry_data)[0] & 0x0FFFFFFF

        return chain

    def read_fat_file(self, start_cluster: int, file_size: int) -> bytes:
        """Read FAT file"""
        chain = self.get_fat_cluster_chain(start_cluster)

        data = bytearray()
        bytes_read = 0

        for cluster in chain:
            if bytes_read >= file_size:
                break

            # Calculate cluster offset
            cluster_offset = self.partition_offset + self.data_area_offset
            cluster_offset += (cluster - 2) * self.cluster_size

            read_size = min(self.cluster_size, file_size - bytes_read)
            chunk = self.disk.read(cluster_offset, read_size)
            data.extend(chunk)
            bytes_read += len(chunk)

        return bytes(data[:file_size])
