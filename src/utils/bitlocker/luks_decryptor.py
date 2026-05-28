# -*- coding: utf-8 -*-
"""
LUKS Decryptor - Unified LUKS decryption class

Provides a high-level API for decrypting LUKS volumes from
E01 images, RAW images, and virtual disk images.

Usage:
    decryptor = LUKSDecryptor.from_raw_image("disk.dd", partition_index=0)
    result = decryptor.unlock_with_passphrase("my-passphrase")

    if result.success:
        reader = decryptor.get_decrypted_reader()
        data = reader.read(0, 512)
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import logging

from .luks_backend import LUKSBackend, is_luks_partition
from .bitlocker_backend import PartitionSliceReader
from .unified_disk_reader import (
    UnifiedDiskReader, PartitionInfo, DiskError
)

logger = logging.getLogger(__name__)


@dataclass
class LUKSUnlockResult:
    """LUKS unlock result"""
    success: bool
    error_message: Optional[str] = None
    volume_info: Optional[Dict[str, Any]] = None

    def __bool__(self):
        return self.success


class LUKSDecryptor:
    """
    Unified LUKS decryption class

    Supports LUKS1 and LUKS2 volumes with passphrase-based unlock.
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

        self._luks_backend: Optional[LUKSBackend] = None

        try:
            self._initialize()
        except Exception:
            if self._disk_backend:
                try:
                    self._disk_backend.close()
                except Exception:
                    pass
                self._disk_backend = None
            raise

    def _initialize(self) -> None:
        try:
            from dissect.fve.luks import LUKS
        except ImportError:
            raise DiskError(
                "dissect.fve is not installed. "
                "Install with: pip install dissect.fve"
            )

        slice_reader = PartitionSliceReader(
            self._disk_backend,
            self._partition_offset,
            self._partition_size
        )

        try:
            self._luks_backend = LUKSBackend(slice_reader)
        except Exception as e:
            raise DiskError(f"Failed to initialize LUKS decryptor: {e}")

    # ========== Factory Methods ==========

    @classmethod
    def from_e01(
        cls,
        e01_path: str,
        partition_index: int = 0
    ) -> 'LUKSDecryptor':
        """Create LUKSDecryptor from E01 image"""
        from .disk_backends import E01DiskBackend

        backend = E01DiskBackend(e01_path)
        return cls._from_backend(backend, partition_index)

    @classmethod
    def from_raw_image(
        cls,
        image_path: str,
        partition_offset: int = 0,
        partition_size: int = None
    ) -> 'LUKSDecryptor':
        """Create LUKSDecryptor from RAW/DD image"""
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
    def from_vmdk(
        cls,
        vmdk_path: str,
        partition_index: int = 0
    ) -> 'LUKSDecryptor':
        """Create LUKSDecryptor from VMDK image"""
        from .disk_backends import VMDKDiskBackend

        backend = VMDKDiskBackend(vmdk_path)
        return cls._from_backend(backend, partition_index)

    @classmethod
    def from_vhd(
        cls,
        vhd_path: str,
        partition_index: int = 0
    ) -> 'LUKSDecryptor':
        """Create LUKSDecryptor from VHD image"""
        from .disk_backends import VHDDiskBackend

        backend = VHDDiskBackend(vhd_path)
        return cls._from_backend(backend, partition_index)

    @classmethod
    def from_vhdx(
        cls,
        vhdx_path: str,
        partition_index: int = 0
    ) -> 'LUKSDecryptor':
        """Create LUKSDecryptor from VHDX image"""
        from .disk_backends import VHDXDiskBackend

        backend = VHDXDiskBackend(vhdx_path)
        return cls._from_backend(backend, partition_index)

    @classmethod
    def from_qcow2(
        cls,
        qcow2_path: str,
        partition_index: int = 0
    ) -> 'LUKSDecryptor':
        """Create LUKSDecryptor from QCOW2 image"""
        from .disk_backends import QCOW2DiskBackend

        backend = QCOW2DiskBackend(qcow2_path)
        return cls._from_backend(backend, partition_index)

    @classmethod
    def from_vdi(
        cls,
        vdi_path: str,
        partition_index: int = 0
    ) -> 'LUKSDecryptor':
        """Create LUKSDecryptor from VDI image"""
        from .disk_backends import VDIDiskBackend

        backend = VDIDiskBackend(vdi_path)
        return cls._from_backend(backend, partition_index)

    @classmethod
    def from_partition(
        cls,
        disk_backend: UnifiedDiskReader,
        partition_info: PartitionInfo
    ) -> 'LUKSDecryptor':
        """Create LUKSDecryptor from partition information"""
        return cls(
            disk_backend=disk_backend,
            partition_offset=partition_info.offset,
            partition_size=partition_info.size,
            partition_index=partition_info.index
        )

    @classmethod
    def _from_backend(
        cls,
        backend: UnifiedDiskReader,
        partition_index: int
    ) -> 'LUKSDecryptor':
        """Common factory logic: detect partitions and find LUKS"""
        from .bitlocker_decryptor import BitLockerDecryptor

        partitions = BitLockerDecryptor._detect_partitions(backend)

        if partition_index >= len(partitions):
            backend.close()
            raise DiskError(f"Partition {partition_index} not found")

        partition = partitions[partition_index]

        if partition.filesystem != 'LUKS':
            backend.close()
            raise DiskError(
                f"Partition {partition_index} is not LUKS encrypted "
                f"(filesystem: {partition.filesystem})"
            )

        return cls(
            disk_backend=backend,
            partition_offset=partition.offset,
            partition_size=partition.size,
            partition_index=partition_index
        )

    # ========== Unlock ==========

    def unlock_with_passphrase(self, passphrase: str) -> LUKSUnlockResult:
        """Unlock LUKS volume with passphrase"""
        if not self._luks_backend:
            return LUKSUnlockResult(
                success=False,
                error_message="LUKS backend not initialized"
            )

        try:
            success = self._luks_backend.unlock_with_passphrase(passphrase)

            if success:
                vol_info = self._luks_backend.get_volume_info()
                return LUKSUnlockResult(
                    success=True,
                    volume_info={
                        'version': vol_info.version,
                        'cipher': vol_info.cipher,
                        'uuid': vol_info.uuid,
                        'decrypted_size': self._luks_backend.get_size(),
                    }
                )
            else:
                return LUKSUnlockResult(
                    success=False,
                    error_message="Invalid passphrase"
                )

        except Exception as e:
            return LUKSUnlockResult(
                success=False,
                error_message=str(e)
            )

    # ========== Decrypted Volume Access ==========

    def get_decrypted_reader(self) -> UnifiedDiskReader:
        """Return decrypted UnifiedDiskReader"""
        if not self._luks_backend:
            raise DiskError("LUKS backend not initialized")

        if self._luks_backend.is_locked():
            raise DiskError(
                "Volume is still locked. Call unlock_with_passphrase() first."
            )

        return self._luks_backend

    def is_locked(self) -> bool:
        if not self._luks_backend:
            return True
        return self._luks_backend.is_locked()

    # ========== Resource Management ==========

    def close(self) -> None:
        if self._luks_backend:
            self._luks_backend.close()
            self._luks_backend = None

        if self._disk_backend:
            try:
                self._disk_backend.close()
            except Exception:
                pass
            self._disk_backend = None

    def __enter__(self) -> 'LUKSDecryptor':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False
