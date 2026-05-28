# -*- coding: utf-8 -*-
"""
BitLocker & LUKS Module for Forensic Collector

Detection and decryption support for BitLocker and LUKS encrypted volumes.

Main Classes:
- BitLockerDecryptor: High-level BitLocker decryption API
- LUKSDecryptor: High-level LUKS decryption API
- BitLockerBackend: dissect.fve BDE wrapper
- LUKSBackend: dissect.fve LUKS wrapper
- PhysicalDiskBackend: Windows physical disk access
- VMDKDiskBackend, VHDDiskBackend, etc.: Virtual disk backends

Supported Key Types (BitLocker):
- Recovery Password (48-digit number)
- Password (regular password)
- BEK File (.BEK startup key file)

Supported Key Types (LUKS):
- Passphrase

Usage:
    from utils.bitlocker import (
        detect_bitlocker_on_system_drive,
        BitLockerDecryptor,
        BitLockerKeyType,
        is_pybde_installed
    )

    # Detect BitLocker volume
    result = detect_bitlocker_on_system_drive()
    if result.is_encrypted:
        print(f"BitLocker detected at partition {result.partition_index}")

    # Decryption
    if is_pybde_installed():
        decryptor = BitLockerDecryptor.from_physical_disk(0, result.partition_index)
        unlock_result = decryptor.unlock_with_recovery_password("<YOUR-RECOVERY-KEY>")
        if unlock_result.success:
            reader = decryptor.get_decrypted_reader()
"""

# Exception classes
from .unified_disk_reader import (
    BitLockerError,
    BitLockerKeyRequired,
    BitLockerInvalidKey,
    BitLockerUnsupportedProtector,
    DiskError,
    DiskNotFoundError,
    DiskPermissionError,
    DiskReadError,
    PartitionInfo
)

# Key types
from .bitlocker_backend import (
    BitLockerKeyType,
    BitLockerVolumeInfo,
    is_pybde_available,
    is_fve_available
)

# High-level BitLocker API
from .bitlocker_decryptor import (
    BitLockerDecryptor,
    BitLockerUnlockResult,
    BitLockerPartitionInfo
)

# LUKS support
from .luks_backend import (
    LUKSBackend,
    LUKSVolumeInfo,
    is_luks_partition
)

from .luks_decryptor import (
    LUKSDecryptor,
    LUKSUnlockResult
)

# Utilities
from .bitlocker_utils import (
    detect_bitlocker_on_system_drive,
    detect_bitlocker_partitions,
    is_pybde_installed,
    format_recovery_password,
    validate_recovery_password,
    BitLockerVolumeDetectionResult,
    # manage-bde based auto unlock/re-encryption
    ManageBdeResult,
    check_admin_privileges,
    get_bitlocker_status,
    disable_bitlocker,
    enable_bitlocker
)

# Disk backends
from .disk_backends import (
    PhysicalDiskBackend,
    E01DiskBackend,
    RAWImageBackend,
    VMDKDiskBackend,
    VHDDiskBackend,
    VHDXDiskBackend,
    QCOW2DiskBackend,
    VDIDiskBackend,
    create_disk_backend
)

__all__ = [
    # Exceptions
    'BitLockerError',
    'BitLockerKeyRequired',
    'BitLockerInvalidKey',
    'BitLockerUnsupportedProtector',
    'DiskError',
    'DiskNotFoundError',
    'DiskPermissionError',
    'DiskReadError',

    # Data classes
    'BitLockerKeyType',
    'BitLockerVolumeInfo',
    'BitLockerUnlockResult',
    'BitLockerPartitionInfo',
    'BitLockerVolumeDetectionResult',
    'PartitionInfo',

    # BitLocker main class
    'BitLockerDecryptor',

    # LUKS
    'LUKSBackend',
    'LUKSVolumeInfo',
    'LUKSDecryptor',
    'LUKSUnlockResult',
    'is_luks_partition',

    # Utility functions
    'detect_bitlocker_on_system_drive',
    'detect_bitlocker_partitions',
    'is_pybde_installed',
    'is_pybde_available',
    'is_fve_available',
    'format_recovery_password',
    'validate_recovery_password',
    # manage-bde based auto unlock/re-encryption
    'ManageBdeResult',
    'check_admin_privileges',
    'get_bitlocker_status',
    'disable_bitlocker',
    'enable_bitlocker',

    # Disk backends
    'PhysicalDiskBackend',
    'E01DiskBackend',
    'RAWImageBackend',
    'VMDKDiskBackend',
    'VHDDiskBackend',
    'VHDXDiskBackend',
    'QCOW2DiskBackend',
    'VDIDiskBackend',
    'create_disk_backend',
]
