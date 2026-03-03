# -*- coding: utf-8 -*-
"""
BitLocker Module for Forensic Collector

Detection and decryption support for BitLocker encrypted volumes.

Main Classes:
- BitLockerDecryptor: High-level decryption API
- BitLockerBackend: pybde wrapper
- PhysicalDiskBackend: Windows physical disk access

Supported Key Types:
- Recovery Password (48-digit number)
- Password (regular password)
- BEK File (.BEK startup key file)

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
        # Recovery password: 8 groups of 6 digits separated by dashes
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
    is_pybde_available
)

# High-level API
from .bitlocker_decryptor import (
    BitLockerDecryptor,
    BitLockerUnlockResult,
    BitLockerPartitionInfo
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

    # Main class
    'BitLockerDecryptor',

    # Utility functions
    'detect_bitlocker_on_system_drive',
    'detect_bitlocker_partitions',
    'is_pybde_installed',
    'is_pybde_available',
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
    'create_disk_backend',
]
