# -*- coding: utf-8 -*-
"""
BitLocker Decryptor - Unified BitLocker decryption class

Provides a high-level API for decrypting BitLocker volumes from
physical disks, E01 images, and RAW images.

Usage:
    decryptor = BitLockerDecryptor.from_physical_disk(0, partition_index=0)
    result = decryptor.unlock_with_recovery_password("123456-234567-...")

    if result.success:
        reader = decryptor.get_decrypted_reader()
        data = reader.read(0, 512)
"""

from typing import Optional, Union, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum
import logging

from .bitlocker_backend import (
    BitLockerBackend, BitLockerKeyType, BitLockerVolumeInfo,
    PartitionSliceReader, is_pybde_available
)
from .unified_disk_reader import (
    UnifiedDiskReader, PartitionInfo, BitLockerError
)

logger = logging.getLogger(__name__)


@dataclass
class BitLockerUnlockResult:
    """BitLocker unlock result"""
    success: bool
    key_type: Optional[BitLockerKeyType] = None
    error_message: Optional[str] = None
    volume_info: Optional[Dict[str, Any]] = None

    def __bool__(self):
        return self.success


@dataclass
class BitLockerPartitionInfo:
    """BitLocker partition information"""
    partition_index: int
    offset: int
    size: int
    encryption_method: str = ""
    volume_identifier: str = ""
    key_protector_count: int = 0
    is_locked: bool = True
    supported_key_types: List[str] = field(default_factory=list)


class BitLockerDecryptor:
    """
    Unified BitLocker decryption class

    Supported Key Types:
    - Recovery Password (48-digit number)
    - Password (regular password)
    - BEK File (.BEK startup key file)

    Not Supported:
    - TPM (hardware dependent)
    """

    def __init__(
        self,
        disk_backend: UnifiedDiskReader,
        partition_offset: int,
        partition_size: int,
        partition_index: int = 0
    ):
        self._disk_backend = disk_backend
        self._partition_offset = partition_offset
        self._partition_size = partition_size
        self._partition_index = partition_index

        self._bitlocker_backend: Optional[BitLockerBackend] = None
        self._partition_info: Optional[BitLockerPartitionInfo] = None

        try:
            self._initialize()
        except Exception:
            # Prevent disk backend leak if initialization fails
            if self._disk_backend:
                try:
                    self._disk_backend.close()
                except Exception:
                    pass
                self._disk_backend = None
            raise

    def _initialize(self) -> None:
        if not is_pybde_available():
            raise BitLockerError(
                "dissect.fve is not installed. "
                "Install with: pip install dissect.fve"
            )

        slice_reader = PartitionSliceReader(
            self._disk_backend,
            self._partition_offset,
            self._partition_size
        )

        try:
            self._bitlocker_backend = BitLockerBackend(slice_reader)
            self._load_partition_info()
        except Exception as e:
            raise BitLockerError(f"Failed to initialize BitLocker decryptor: {e}")

    def _load_partition_info(self) -> None:
        volume_info = self._bitlocker_backend.get_volume_info()
        protectors = self._bitlocker_backend.get_key_protectors()

        supported = set()
        for p in protectors:
            ptype = p.get('type', '').lower()
            if 'recovery' in ptype:
                supported.add('recovery_password')
            if 'password' in ptype and 'recovery' not in ptype:
                supported.add('password')
            if 'external' in ptype or 'startup' in ptype:
                supported.add('bek_file')
            if 'clear' in ptype:
                supported.add('clear_key')

        if not supported:
            supported = {'recovery_password', 'password', 'bek_file'}

        self._partition_info = BitLockerPartitionInfo(
            partition_index=self._partition_index,
            offset=self._partition_offset,
            size=self._partition_size,
            encryption_method=volume_info.encryption_method,
            volume_identifier=volume_info.volume_identifier,
            key_protector_count=volume_info.key_protector_count,
            is_locked=volume_info.is_locked,
            supported_key_types=list(supported)
        )

    # ========== Factory Methods ==========

    @classmethod
    def from_detection_result(
        cls,
        drive_number: int,
        detection_result: 'BitLockerVolumeDetectionResult'
    ) -> 'BitLockerDecryptor':
        """Create BitLockerDecryptor using cached detection result.

        Avoids re-scanning the partition table, which can fail on GPT disks
        or when the OS caches VBR differently between reads.
        """
        from .disk_backends import PhysicalDiskBackend

        if not detection_result.is_encrypted:
            raise BitLockerError("Detection result indicates no BitLocker encryption")

        if detection_result.partition_offset is None or detection_result.partition_size is None:
            raise BitLockerError("Detection result missing partition offset/size")
        if detection_result.partition_size <= 0:
            raise BitLockerError(f"Invalid partition size: {detection_result.partition_size}")

        backend = PhysicalDiskBackend(drive_number)
        return cls(
            disk_backend=backend,
            partition_offset=detection_result.partition_offset,
            partition_size=detection_result.partition_size,
            partition_index=detection_result.partition_index
        )

    @classmethod
    def from_physical_disk(
        cls,
        drive_number: int,
        partition_index: int = 0
    ) -> 'BitLockerDecryptor':
        """Create BitLockerDecryptor from physical disk (re-scans partitions)"""
        from .disk_backends import PhysicalDiskBackend

        backend = PhysicalDiskBackend(drive_number)
        partitions = cls._detect_partitions(backend)

        if partition_index >= len(partitions):
            backend.close()
            raise BitLockerError(f"Partition {partition_index} not found")

        partition = partitions[partition_index]

        if partition.filesystem != 'BitLocker':
            backend.close()
            raise BitLockerError(
                f"Partition {partition_index} is not BitLocker encrypted "
                f"(filesystem: {partition.filesystem})"
            )

        return cls(
            disk_backend=backend,
            partition_offset=partition.offset,
            partition_size=partition.size,
            partition_index=partition_index
        )

    @classmethod
    def from_e01(
        cls,
        e01_path: str,
        partition_index: int = 0
    ) -> 'BitLockerDecryptor':
        """Create BitLockerDecryptor from E01 image"""
        from .disk_backends import E01DiskBackend

        backend = E01DiskBackend(e01_path)
        partitions = cls._detect_partitions(backend)

        if partition_index >= len(partitions):
            backend.close()
            raise BitLockerError(f"Partition {partition_index} not found")

        partition = partitions[partition_index]

        if partition.filesystem != 'BitLocker':
            backend.close()
            raise BitLockerError(
                f"Partition {partition_index} is not BitLocker encrypted "
                f"(filesystem: {partition.filesystem})"
            )

        return cls(
            disk_backend=backend,
            partition_offset=partition.offset,
            partition_size=partition.size,
            partition_index=partition_index
        )

    @classmethod
    def from_vmdk(
        cls,
        vmdk_path: str,
        partition_index: int = 0
    ) -> 'BitLockerDecryptor':
        """Create BitLockerDecryptor from VMDK image"""
        from .disk_backends import VMDKDiskBackend

        backend = VMDKDiskBackend(vmdk_path)
        partitions = cls._detect_partitions(backend)

        if partition_index >= len(partitions):
            backend.close()
            raise BitLockerError(f"Partition {partition_index} not found")

        partition = partitions[partition_index]

        if partition.filesystem != 'BitLocker':
            backend.close()
            raise BitLockerError(
                f"Partition {partition_index} is not BitLocker encrypted "
                f"(filesystem: {partition.filesystem})"
            )

        return cls(
            disk_backend=backend,
            partition_offset=partition.offset,
            partition_size=partition.size,
            partition_index=partition_index
        )

    @classmethod
    def from_vhd(
        cls,
        vhd_path: str,
        partition_index: int = 0
    ) -> 'BitLockerDecryptor':
        """Create BitLockerDecryptor from VHD image"""
        from .disk_backends import VHDDiskBackend

        backend = VHDDiskBackend(vhd_path)
        partitions = cls._detect_partitions(backend)

        if partition_index >= len(partitions):
            backend.close()
            raise BitLockerError(f"Partition {partition_index} not found")

        partition = partitions[partition_index]

        if partition.filesystem != 'BitLocker':
            backend.close()
            raise BitLockerError(
                f"Partition {partition_index} is not BitLocker encrypted "
                f"(filesystem: {partition.filesystem})"
            )

        return cls(
            disk_backend=backend,
            partition_offset=partition.offset,
            partition_size=partition.size,
            partition_index=partition_index
        )

    @classmethod
    def from_vhdx(
        cls,
        vhdx_path: str,
        partition_index: int = 0
    ) -> 'BitLockerDecryptor':
        """Create BitLockerDecryptor from VHDX image"""
        from .disk_backends import VHDXDiskBackend

        backend = VHDXDiskBackend(vhdx_path)
        partitions = cls._detect_partitions(backend)

        if partition_index >= len(partitions):
            backend.close()
            raise BitLockerError(f"Partition {partition_index} not found")

        partition = partitions[partition_index]

        if partition.filesystem != 'BitLocker':
            backend.close()
            raise BitLockerError(
                f"Partition {partition_index} is not BitLocker encrypted "
                f"(filesystem: {partition.filesystem})"
            )

        return cls(
            disk_backend=backend,
            partition_offset=partition.offset,
            partition_size=partition.size,
            partition_index=partition_index
        )

    @classmethod
    def from_qcow2(
        cls,
        qcow2_path: str,
        partition_index: int = 0
    ) -> 'BitLockerDecryptor':
        """Create BitLockerDecryptor from QCOW2 image"""
        from .disk_backends import QCOW2DiskBackend

        backend = QCOW2DiskBackend(qcow2_path)
        partitions = cls._detect_partitions(backend)

        if partition_index >= len(partitions):
            backend.close()
            raise BitLockerError(f"Partition {partition_index} not found")

        partition = partitions[partition_index]

        if partition.filesystem != 'BitLocker':
            backend.close()
            raise BitLockerError(
                f"Partition {partition_index} is not BitLocker encrypted "
                f"(filesystem: {partition.filesystem})"
            )

        return cls(
            disk_backend=backend,
            partition_offset=partition.offset,
            partition_size=partition.size,
            partition_index=partition_index
        )

    @classmethod
    def from_vdi(
        cls,
        vdi_path: str,
        partition_index: int = 0
    ) -> 'BitLockerDecryptor':
        """Create BitLockerDecryptor from VDI image"""
        from .disk_backends import VDIDiskBackend

        backend = VDIDiskBackend(vdi_path)
        partitions = cls._detect_partitions(backend)

        if partition_index >= len(partitions):
            backend.close()
            raise BitLockerError(f"Partition {partition_index} not found")

        partition = partitions[partition_index]

        if partition.filesystem != 'BitLocker':
            backend.close()
            raise BitLockerError(
                f"Partition {partition_index} is not BitLocker encrypted "
                f"(filesystem: {partition.filesystem})"
            )

        return cls(
            disk_backend=backend,
            partition_offset=partition.offset,
            partition_size=partition.size,
            partition_index=partition_index
        )

    @classmethod
    def from_raw_image(
        cls,
        image_path: str,
        partition_offset: int = 0,
        partition_size: int = None
    ) -> 'BitLockerDecryptor':
        """Create BitLockerDecryptor from RAW/DD image"""
        from .disk_backends import RAWImageBackend

        backend = RAWImageBackend(image_path)

        if partition_size is None:
            partition_size = backend.get_size() - partition_offset

        return cls(
            disk_backend=backend,
            partition_offset=partition_offset,
            partition_size=partition_size,
            partition_index=0
        )

    @classmethod
    def from_partition(
        cls,
        disk_backend: UnifiedDiskReader,
        partition_info: PartitionInfo
    ) -> 'BitLockerDecryptor':
        """Create BitLockerDecryptor from partition information"""
        return cls(
            disk_backend=disk_backend,
            partition_offset=partition_info.offset,
            partition_size=partition_info.size,
            partition_index=partition_info.index
        )

    @classmethod
    def _detect_partitions(cls, backend: UnifiedDiskReader) -> List[PartitionInfo]:
        """Detect partition table (simple implementation)"""
        import struct
        partitions = []

        try:
            # Read MBR
            mbr = backend.read(0, 512)
            if len(mbr) < 512:
                return []

            # Verify MBR signature
            signature = struct.unpack('<H', mbr[510:512])[0]
            if signature != 0xAA55:
                return []

            # Parse partition entries (MBR)
            for i in range(4):
                entry_offset = 446 + i * 16
                entry = mbr[entry_offset:entry_offset + 16]

                partition_type = entry[4]
                if partition_type == 0:
                    continue

                lba_start = struct.unpack('<I', entry[8:12])[0]
                sector_count = struct.unpack('<I', entry[12:16])[0]

                # Detect BitLocker (VBR signature)
                partition_offset = lba_start * 512
                vbr = backend.read(partition_offset, 512)
                filesystem = cls._detect_filesystem(vbr)

                partitions.append(PartitionInfo(
                    index=i,
                    partition_type=partition_type,
                    offset=partition_offset,
                    size=sector_count * 512,
                    lba_start=lba_start,
                    sector_count=sector_count,
                    filesystem=filesystem,
                    is_bootable=(entry[0] & 0x80) != 0
                ))

        except Exception as e:
            logger.warning(f"Failed to detect partitions: {e}")

        return partitions

    @classmethod
    def _detect_filesystem(cls, vbr: bytes) -> str:
        """Detect filesystem from VBR"""
        if len(vbr) < 512:
            return "Unknown"

        # LUKS signature: "LUKS\xba\xbe" at offset 0
        if len(vbr) >= 6 and vbr[:6] == b'LUKS\xba\xbe':
            return "LUKS"

        # BitLocker signature: "-FVE-FS-" at offset 3
        if vbr[3:11] == b'-FVE-FS-':
            return "BitLocker"

        # NTFS signature
        if vbr[3:7] == b'NTFS':
            return "NTFS"

        # FAT32 signature
        if vbr[82:90] == b'FAT32   ':
            return "FAT32"

        # exFAT signature
        if vbr[3:11] == b'EXFAT   ':
            return "exFAT"

        return "Unknown"

    # ========== Unlock Methods ==========

    def unlock_with_recovery_password(self, recovery_password: str) -> BitLockerUnlockResult:
        """Unlock with Recovery Password"""
        if not self._bitlocker_backend:
            return BitLockerUnlockResult(
                success=False,
                error_message="BitLocker backend not initialized"
            )

        try:
            self._bitlocker_backend.set_recovery_password(recovery_password)
            self._bitlocker_backend.unlock()

            return BitLockerUnlockResult(
                success=True,
                key_type=BitLockerKeyType.RECOVERY_PASSWORD,
                volume_info=self._get_volume_info_dict()
            )

        except Exception as e:
            error_msg = str(e) or f"Recovery password unlock failed ({type(e).__name__})"
            logger.error(f"unlock_with_recovery_password failed: {error_msg}")
            return BitLockerUnlockResult(
                success=False,
                key_type=BitLockerKeyType.RECOVERY_PASSWORD,
                error_message=error_msg
            )

    def unlock_with_password(self, password: str) -> BitLockerUnlockResult:
        """Unlock with regular password"""
        if not self._bitlocker_backend:
            return BitLockerUnlockResult(
                success=False,
                error_message="BitLocker backend not initialized"
            )

        try:
            self._bitlocker_backend.set_password(password)
            self._bitlocker_backend.unlock()

            return BitLockerUnlockResult(
                success=True,
                key_type=BitLockerKeyType.PASSWORD,
                volume_info=self._get_volume_info_dict()
            )

        except Exception as e:
            error_msg = str(e) or f"Password unlock failed ({type(e).__name__})"
            logger.error(f"unlock_with_password failed: {error_msg}")
            return BitLockerUnlockResult(
                success=False,
                key_type=BitLockerKeyType.PASSWORD,
                error_message=error_msg
            )

    def unlock_with_bek_file(self, bek_path: str) -> BitLockerUnlockResult:
        """Unlock with .BEK startup key file"""
        if not self._bitlocker_backend:
            return BitLockerUnlockResult(
                success=False,
                error_message="BitLocker backend not initialized"
            )

        try:
            self._bitlocker_backend.read_startup_key(bek_path)
            self._bitlocker_backend.unlock()

            return BitLockerUnlockResult(
                success=True,
                key_type=BitLockerKeyType.BEK_FILE,
                volume_info=self._get_volume_info_dict()
            )

        except Exception as e:
            error_msg = str(e) or f"BEK file unlock failed ({type(e).__name__})"
            logger.error(f"unlock_with_bek_file failed: {error_msg}")
            return BitLockerUnlockResult(
                success=False,
                key_type=BitLockerKeyType.BEK_FILE,
                error_message=error_msg
            )

    def unlock(
        self,
        key_type: BitLockerKeyType,
        key_value: str = "",
        bek_path: str = ""
    ) -> BitLockerUnlockResult:
        """Unified unlock method"""
        if key_type == BitLockerKeyType.RECOVERY_PASSWORD:
            return self.unlock_with_recovery_password(key_value)
        elif key_type == BitLockerKeyType.PASSWORD:
            return self.unlock_with_password(key_value)
        elif key_type == BitLockerKeyType.BEK_FILE:
            return self.unlock_with_bek_file(bek_path)
        else:
            return BitLockerUnlockResult(
                success=False,
                error_message=f"Unsupported key type: {key_type}"
            )

    # ========== Decrypted Volume Access ==========

    def get_decrypted_reader(self) -> UnifiedDiskReader:
        """Return decrypted UnifiedDiskReader"""
        if not self._bitlocker_backend:
            raise BitLockerError("BitLocker backend not initialized")

        if self._bitlocker_backend.is_locked():
            raise BitLockerError(
                "Volume is still locked. Call unlock_with_*() first."
            )

        return self._bitlocker_backend

    # ========== Information Retrieval ==========

    def get_partition_info(self) -> BitLockerPartitionInfo:
        return self._partition_info or BitLockerPartitionInfo(
            partition_index=self._partition_index,
            offset=self._partition_offset,
            size=self._partition_size
        )

    def is_locked(self) -> bool:
        if not self._bitlocker_backend:
            return True
        return self._bitlocker_backend.is_locked()

    def _get_volume_info_dict(self) -> Dict[str, Any]:
        if not self._bitlocker_backend:
            return {}

        vol_info = self._bitlocker_backend.get_volume_info()
        return {
            'encryption_method': vol_info.encryption_method,
            'volume_identifier': vol_info.volume_identifier,
            'decrypted_size': self._bitlocker_backend.get_size(),
            'partition_offset': self._partition_offset,
            'partition_size': self._partition_size
        }

    # ========== Resource Management ==========

    def close(self) -> None:
        if self._bitlocker_backend:
            self._bitlocker_backend.close()
            self._bitlocker_backend = None

        if self._disk_backend:
            try:
                self._disk_backend.close()
            except Exception:
                pass
            self._disk_backend = None

    def __enter__(self) -> 'BitLockerDecryptor':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False
