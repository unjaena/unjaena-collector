# -*- coding: utf-8 -*-
"""
BitLocker Module for Forensic Collector

BitLocker 암호화 볼륨 감지 및 복호화 지원

주요 클래스:
- BitLockerDecryptor: 고수준 복호화 API
- BitLockerBackend: pybde 래퍼
- PhysicalDiskBackend: Windows 물리 디스크 접근

지원 키 타입:
- Recovery Password (48자리 숫자)
- Password (일반 비밀번호)
- BEK File (.BEK 시작 키 파일)

Usage:
    from utils.bitlocker import (
        detect_bitlocker_on_system_drive,
        BitLockerDecryptor,
        BitLockerKeyType,
        is_pybde_installed
    )

    # BitLocker 볼륨 감지
    result = detect_bitlocker_on_system_drive()
    if result.is_encrypted:
        print(f"BitLocker detected at partition {result.partition_index}")

    # 복호화
    if is_pybde_installed():
        decryptor = BitLockerDecryptor.from_physical_disk(0, result.partition_index)
        unlock_result = decryptor.unlock_with_recovery_password("123456-234567-...")
        if unlock_result.success:
            reader = decryptor.get_decrypted_reader()
"""

# 예외 클래스
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

# 키 타입
from .bitlocker_backend import (
    BitLockerKeyType,
    BitLockerVolumeInfo,
    is_pybde_available
)

# 고수준 API
from .bitlocker_decryptor import (
    BitLockerDecryptor,
    BitLockerUnlockResult,
    BitLockerPartitionInfo
)

# 유틸리티
from .bitlocker_utils import (
    detect_bitlocker_on_system_drive,
    detect_bitlocker_partitions,
    is_pybde_installed,
    format_recovery_password,
    validate_recovery_password,
    BitLockerVolumeDetectionResult,
    # manage-bde 기반 자동 해제/재암호화
    ManageBdeResult,
    check_admin_privileges,
    get_bitlocker_status,
    disable_bitlocker,
    enable_bitlocker
)

# 디스크 백엔드
from .disk_backends import (
    PhysicalDiskBackend,
    E01DiskBackend,
    RAWImageBackend,
    create_disk_backend
)

__all__ = [
    # 예외
    'BitLockerError',
    'BitLockerKeyRequired',
    'BitLockerInvalidKey',
    'BitLockerUnsupportedProtector',
    'DiskError',
    'DiskNotFoundError',
    'DiskPermissionError',
    'DiskReadError',

    # 데이터 클래스
    'BitLockerKeyType',
    'BitLockerVolumeInfo',
    'BitLockerUnlockResult',
    'BitLockerPartitionInfo',
    'BitLockerVolumeDetectionResult',
    'PartitionInfo',

    # 메인 클래스
    'BitLockerDecryptor',

    # 유틸리티 함수
    'detect_bitlocker_on_system_drive',
    'detect_bitlocker_partitions',
    'is_pybde_installed',
    'is_pybde_available',
    'format_recovery_password',
    'validate_recovery_password',
    # manage-bde 기반 자동 해제/재암호화
    'ManageBdeResult',
    'check_admin_privileges',
    'get_bitlocker_status',
    'disable_bitlocker',
    'enable_bitlocker',

    # 디스크 백엔드
    'PhysicalDiskBackend',
    'E01DiskBackend',
    'RAWImageBackend',
    'create_disk_backend',
]
