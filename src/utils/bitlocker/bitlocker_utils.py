# -*- coding: utf-8 -*-
"""
BitLocker Utilities - BitLocker 볼륨 감지 및 유틸리티 함수

수집 도구에서 BitLocker 암호화 볼륨을 감지하고 처리하기 위한 유틸리티.
"""

import struct
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class BitLockerVolumeDetectionResult:
    """BitLocker 볼륨 감지 결과"""
    is_encrypted: bool = False
    partition_index: int = 0
    partition_offset: int = 0
    partition_size: int = 0
    encryption_method: str = ""
    drive_letter: str = ""
    error: Optional[str] = None


def detect_bitlocker_on_system_drive() -> BitLockerVolumeDetectionResult:
    """
    시스템 드라이브(일반적으로 C:)에서 BitLocker 암호화 감지

    Returns:
        BitLockerVolumeDetectionResult
    """
    import sys
    if sys.platform != 'win32':
        return BitLockerVolumeDetectionResult(
            is_encrypted=False,
            error="BitLocker detection only supported on Windows"
        )

    try:
        # WMI를 통한 BitLocker 상태 확인
        result = _check_bitlocker_via_wmi()
        if result:
            return result

        # WMI 실패 시 직접 디스크 확인
        return _check_bitlocker_direct()

    except Exception as e:
        logger.error(f"BitLocker detection failed: {e}")
        return BitLockerVolumeDetectionResult(
            is_encrypted=False,
            error=str(e)
        )


def _check_bitlocker_via_wmi() -> Optional[BitLockerVolumeDetectionResult]:
    """WMI를 통한 BitLocker 상태 확인"""
    try:
        import wmi
        c = wmi.WMI(namespace="root\\cimv2\\Security\\MicrosoftVolumeEncryption")

        for volume in c.Win32_EncryptableVolume():
            protection_status = volume.ProtectionStatus
            drive_letter = volume.DriveLetter

            # ProtectionStatus: 0=Off, 1=On, 2=Unknown
            if protection_status == 1:
                return BitLockerVolumeDetectionResult(
                    is_encrypted=True,
                    drive_letter=drive_letter or "C:",
                    encryption_method=_get_encryption_method_wmi(volume)
                )

        return None

    except ImportError:
        logger.debug("WMI module not available, falling back to direct check")
        return None
    except Exception as e:
        logger.debug(f"WMI BitLocker check failed: {e}")
        return None


def _get_encryption_method_wmi(volume) -> str:
    """WMI 볼륨에서 암호화 방식 조회"""
    try:
        method_code = volume.EncryptionMethod
        methods = {
            0: "None",
            1: "AES-128-CBC + Diffuser",
            2: "AES-256-CBC + Diffuser",
            3: "AES-128-CBC",
            4: "AES-256-CBC",
            5: "AES-128-XTS",
            6: "AES-256-XTS",
            7: "XTS-AES-128",
            8: "XTS-AES-256"
        }
        return methods.get(method_code, f"Unknown ({method_code})")
    except:
        return "Unknown"


def _check_bitlocker_direct() -> BitLockerVolumeDetectionResult:
    """물리 디스크를 직접 읽어서 BitLocker 감지"""
    try:
        from .disk_backends import PhysicalDiskBackend

        # PhysicalDrive0 (시스템 디스크) 확인
        backend = PhysicalDiskBackend(0)

        try:
            # MBR 읽기
            mbr = backend.read(0, 512)
            if len(mbr) < 512:
                return BitLockerVolumeDetectionResult(is_encrypted=False)

            # MBR 시그니처 확인
            signature = struct.unpack('<H', mbr[510:512])[0]
            if signature != 0xAA55:
                return BitLockerVolumeDetectionResult(
                    is_encrypted=False,
                    error="Invalid MBR signature"
                )

            # GPT 보호 MBR 확인 (파티션 타입 0xEE = GPT Protective)
            # 첫 번째 파티션 엔트리의 타입 확인
            first_partition_type = mbr[446 + 4]  # 첫 번째 파티션의 타입
            is_gpt = first_partition_type == 0xEE

            if is_gpt:
                # GPT 디스크 처리
                logger.debug("GPT disk detected, checking GPT partitions")
                return _check_bitlocker_gpt(backend)

            # MBR 파티션 확인
            logger.debug("MBR disk detected, checking MBR partitions")
            for i in range(4):
                entry_offset = 446 + i * 16
                entry = mbr[entry_offset:entry_offset + 16]

                partition_type = entry[4]
                if partition_type == 0:
                    continue

                lba_start = struct.unpack('<I', entry[8:12])[0]
                sector_count = struct.unpack('<I', entry[12:16])[0]
                partition_offset = lba_start * 512
                partition_size = sector_count * 512

                # VBR에서 BitLocker 시그니처 확인
                vbr = backend.read(partition_offset, 512)
                if _is_bitlocker_vbr(vbr):
                    logger.info(f"BitLocker detected on MBR partition {i}")
                    return BitLockerVolumeDetectionResult(
                        is_encrypted=True,
                        partition_index=i,
                        partition_offset=partition_offset,
                        partition_size=partition_size
                    )

            return BitLockerVolumeDetectionResult(is_encrypted=False)

        finally:
            backend.close()

    except Exception as e:
        logger.warning(f"Direct BitLocker check failed: {e}")
        return BitLockerVolumeDetectionResult(
            is_encrypted=False,
            error=str(e)
        )


def _check_bitlocker_gpt(backend) -> BitLockerVolumeDetectionResult:
    """GPT 디스크에서 BitLocker 감지"""
    try:
        # GPT 헤더 (LBA 1)
        gpt_header = backend.read(512, 512)

        if gpt_header[:8] != b'EFI PART':
            logger.debug("Not a valid GPT header")
            return BitLockerVolumeDetectionResult(is_encrypted=False)

        logger.debug("Valid GPT header found")

        # 파티션 엔트리 시작 LBA
        entries_lba = struct.unpack('<Q', gpt_header[72:80])[0]
        num_entries = struct.unpack('<I', gpt_header[80:84])[0]
        entry_size = struct.unpack('<I', gpt_header[84:88])[0]

        logger.debug(f"GPT: {num_entries} partition entries, size={entry_size}")

        # 파티션 엔트리 읽기
        entries_offset = entries_lba * 512
        entries_data = backend.read(entries_offset, num_entries * entry_size)

        partitions_found = 0
        for i in range(min(num_entries, 128)):  # 최대 128개 확인
            entry_offset = i * entry_size
            entry = entries_data[entry_offset:entry_offset + entry_size]

            # 파티션 타입 GUID (offset 0-16)
            type_guid = entry[:16]

            # 빈 엔트리 스킵
            if type_guid == b'\x00' * 16:
                continue

            partitions_found += 1

            # 파티션 오프셋 및 크기
            first_lba = struct.unpack('<Q', entry[32:40])[0]
            last_lba = struct.unpack('<Q', entry[40:48])[0]
            partition_offset = first_lba * 512
            partition_size = (last_lba - first_lba + 1) * 512

            # VBR에서 BitLocker 시그니처 확인
            vbr = backend.read(partition_offset, 512)
            is_bitlocker = _is_bitlocker_vbr(vbr)

            logger.debug(
                f"GPT Partition {i}: offset={partition_offset}, "
                f"size={partition_size // (1024*1024*1024):.1f}GB, "
                f"BitLocker={is_bitlocker}"
            )

            if is_bitlocker:
                logger.info(f"BitLocker detected on GPT partition {i}")
                return BitLockerVolumeDetectionResult(
                    is_encrypted=True,
                    partition_index=i,
                    partition_offset=partition_offset,
                    partition_size=partition_size
                )

        logger.debug(f"Checked {partitions_found} GPT partitions, no BitLocker found")
        return BitLockerVolumeDetectionResult(is_encrypted=False)

    except Exception as e:
        logger.warning(f"GPT BitLocker check failed: {e}")
        return BitLockerVolumeDetectionResult(is_encrypted=False, error=str(e))


def _is_bitlocker_vbr(vbr: bytes) -> bool:
    """VBR이 BitLocker 암호화되었는지 확인"""
    if len(vbr) < 512:
        return False

    # BitLocker 시그니처: "-FVE-FS-" at offset 3
    return vbr[3:11] == b'-FVE-FS-'


def detect_bitlocker_partitions(drive_number: int = 0) -> List[Dict[str, Any]]:
    """
    지정된 물리 드라이브에서 모든 BitLocker 암호화 파티션 감지

    Args:
        drive_number: 물리 드라이브 번호

    Returns:
        BitLocker 파티션 정보 리스트
    """
    from .disk_backends import PhysicalDiskBackend

    partitions = []

    try:
        backend = PhysicalDiskBackend(drive_number)

        try:
            # MBR 읽기
            mbr = backend.read(0, 512)

            # MBR 시그니처 확인
            signature = struct.unpack('<H', mbr[510:512])[0]

            if signature == 0xAA55:
                # MBR 파티션 테이블
                for i in range(4):
                    entry_offset = 446 + i * 16
                    entry = mbr[entry_offset:entry_offset + 16]

                    partition_type = entry[4]
                    if partition_type == 0:
                        continue

                    lba_start = struct.unpack('<I', entry[8:12])[0]
                    sector_count = struct.unpack('<I', entry[12:16])[0]
                    partition_offset = lba_start * 512
                    partition_size = sector_count * 512

                    vbr = backend.read(partition_offset, 512)
                    is_bitlocker = _is_bitlocker_vbr(vbr)

                    partitions.append({
                        'index': i,
                        'offset': partition_offset,
                        'size': partition_size,
                        'is_bitlocker': is_bitlocker,
                        'filesystem': 'BitLocker' if is_bitlocker else _detect_filesystem(vbr)
                    })
            else:
                # GPT 디스크 처리 (간략화)
                logger.info("GPT disk detected - scanning partitions")

        finally:
            backend.close()

    except Exception as e:
        logger.error(f"Failed to detect BitLocker partitions: {e}")

    return partitions


def _detect_filesystem(vbr: bytes) -> str:
    """VBR에서 파일시스템 감지"""
    if len(vbr) < 512:
        return "Unknown"

    if vbr[3:11] == b'-FVE-FS-':
        return "BitLocker"
    if vbr[3:7] == b'NTFS':
        return "NTFS"
    if vbr[82:90] == b'FAT32   ':
        return "FAT32"
    if vbr[3:11] == b'EXFAT   ':
        return "exFAT"

    return "Unknown"


def is_pybde_installed() -> bool:
    """pybde (libbde-python) 설치 여부 확인"""
    try:
        import pybde
        return True
    except ImportError:
        return False


def format_recovery_password(raw_input: str) -> str:
    """
    복구 키 입력값을 표준 형식으로 변환

    입력: "123456234567345678..." 또는 "123456-234567-345678-..."
    출력: "123456-234567-345678-456789-567890-678901-789012-890123"
    """
    # 숫자만 추출
    digits = ''.join(c for c in raw_input if c.isdigit())

    if len(digits) != 48:
        raise ValueError(
            f"Recovery password must be 48 digits, got {len(digits)}"
        )

    # 6자리씩 그룹화
    groups = [digits[i:i+6] for i in range(0, 48, 6)]
    return '-'.join(groups)


def validate_recovery_password(password: str) -> bool:
    """복구 키 형식 검증"""
    try:
        format_recovery_password(password)
        return True
    except ValueError:
        return False


# =============================================================================
# manage-bde 기반 BitLocker 자동 해제/재암호화
# =============================================================================

@dataclass
class ManageBdeResult:
    """manage-bde 실행 결과"""
    success: bool = False
    message: str = ""
    percentage: float = 0.0  # 암호화/복호화 진행률
    protection_status: str = ""  # On, Off, Unknown
    error: Optional[str] = None


def check_admin_privileges() -> bool:
    """관리자 권한 확인"""
    import sys
    if sys.platform != 'win32':
        return False

    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_bitlocker_status(drive: str = "C:") -> ManageBdeResult:
    """
    manage-bde를 사용하여 BitLocker 상태 확인

    Args:
        drive: 드라이브 문자 (예: "C:")

    Returns:
        ManageBdeResult
    """
    import subprocess
    import re
    import sys

    if sys.platform != 'win32':
        return ManageBdeResult(
            success=False,
            error="manage-bde is only available on Windows"
        )

    try:
        result = subprocess.run(
            ['manage-bde', '-status', drive],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        output = result.stdout + result.stderr

        # 보호 상태 파싱
        protection_status = "Unknown"
        if "Protection On" in output or "보호 설정" in output:
            protection_status = "On"
        elif "Protection Off" in output or "보호 해제" in output:
            protection_status = "Off"

        # 암호화 비율 파싱
        percentage = 0.0
        percentage_match = re.search(r'(\d+(?:\.\d+)?)\s*%', output)
        if percentage_match:
            percentage = float(percentage_match.group(1))

        # 암호화 상태 확인
        is_encrypted = "Fully Encrypted" in output or "완전히 암호화됨" in output
        is_decrypted = "Fully Decrypted" in output or "완전히 해독됨" in output or percentage == 0.0

        if is_encrypted:
            message = "fully_encrypted"
        elif is_decrypted:
            message = "fully_decrypted"
        else:
            message = "in_progress"

        return ManageBdeResult(
            success=True,
            message=message,
            percentage=percentage,
            protection_status=protection_status
        )

    except subprocess.TimeoutExpired:
        return ManageBdeResult(success=False, error="manage-bde timeout")
    except FileNotFoundError:
        return ManageBdeResult(success=False, error="manage-bde not found")
    except Exception as e:
        return ManageBdeResult(success=False, error=str(e))


def disable_bitlocker(
    drive: str = "C:",
    progress_callback: Optional[callable] = None,
    wait_for_completion: bool = True,
    check_interval: int = 10
) -> ManageBdeResult:
    """
    BitLocker 암호화 해제 (manage-bde -off)

    Args:
        drive: 드라이브 문자 (예: "C:")
        progress_callback: 진행률 콜백 함수 (percentage: float, message: str)
        wait_for_completion: 완료까지 대기 여부
        check_interval: 상태 확인 간격 (초)

    Returns:
        ManageBdeResult
    """
    import subprocess
    import time
    import sys

    if sys.platform != 'win32':
        return ManageBdeResult(
            success=False,
            error="manage-bde is only available on Windows"
        )

    if not check_admin_privileges():
        return ManageBdeResult(
            success=False,
            error="Administrator privileges required"
        )

    # 현재 상태 확인
    status = get_bitlocker_status(drive)
    if not status.success:
        return status

    if status.message == "fully_decrypted":
        logger.info(f"Drive {drive} is already decrypted")
        return ManageBdeResult(
            success=True,
            message="already_decrypted",
            percentage=0.0,
            protection_status="Off"
        )

    try:
        # BitLocker 해제 시작
        logger.info(f"Starting BitLocker decryption on {drive}")
        if progress_callback:
            progress_callback(0.0, f"BitLocker 해제 시작: {drive}")

        result = subprocess.run(
            ['manage-bde', '-off', drive],
            capture_output=True,
            text=True,
            timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        if result.returncode != 0:
            error_msg = result.stderr or result.stdout
            return ManageBdeResult(
                success=False,
                error=f"manage-bde -off failed: {error_msg}"
            )

        if not wait_for_completion:
            return ManageBdeResult(
                success=True,
                message="decryption_started",
                protection_status="Off"
            )

        # 완료까지 대기
        while True:
            time.sleep(check_interval)
            status = get_bitlocker_status(drive)

            if not status.success:
                return status

            remaining = 100.0 - status.percentage if status.percentage > 0 else 0.0
            logger.info(f"BitLocker decryption progress: {remaining:.1f}% remaining")

            if progress_callback:
                progress_callback(remaining, f"복호화 진행 중: {remaining:.1f}% 남음")

            if status.message == "fully_decrypted" or status.percentage == 0.0:
                logger.info(f"BitLocker decryption completed on {drive}")
                if progress_callback:
                    progress_callback(100.0, "복호화 완료")
                return ManageBdeResult(
                    success=True,
                    message="decryption_completed",
                    percentage=0.0,
                    protection_status="Off"
                )

    except subprocess.TimeoutExpired:
        return ManageBdeResult(success=False, error="manage-bde timeout")
    except Exception as e:
        return ManageBdeResult(success=False, error=str(e))


def enable_bitlocker(
    drive: str = "C:",
    progress_callback: Optional[callable] = None,
    wait_for_completion: bool = False,
    check_interval: int = 10
) -> ManageBdeResult:
    """
    BitLocker 암호화 활성화 (manage-bde -on)

    Args:
        drive: 드라이브 문자 (예: "C:")
        progress_callback: 진행률 콜백 함수 (percentage: float, message: str)
        wait_for_completion: 완료까지 대기 여부 (기본: False - 백그라운드 암호화)
        check_interval: 상태 확인 간격 (초)

    Returns:
        ManageBdeResult

    Note:
        재암호화는 TPM이 있는 경우 자동으로 키를 사용합니다.
        TPM이 없거나 복구 키가 필요한 경우 추가 설정이 필요할 수 있습니다.
    """
    import subprocess
    import time
    import sys

    if sys.platform != 'win32':
        return ManageBdeResult(
            success=False,
            error="manage-bde is only available on Windows"
        )

    if not check_admin_privileges():
        return ManageBdeResult(
            success=False,
            error="Administrator privileges required"
        )

    # 현재 상태 확인
    status = get_bitlocker_status(drive)
    if not status.success:
        return status

    if status.message == "fully_encrypted":
        logger.info(f"Drive {drive} is already encrypted")
        return ManageBdeResult(
            success=True,
            message="already_encrypted",
            percentage=100.0,
            protection_status="On"
        )

    try:
        # BitLocker 암호화 시작 (TPM 사용)
        logger.info(f"Starting BitLocker encryption on {drive}")
        if progress_callback:
            progress_callback(0.0, f"BitLocker 암호화 시작: {drive}")

        # -UsedSpaceOnly: 사용된 공간만 암호화 (빠름)
        # -SkipHardwareTest: 하드웨어 테스트 건너뛰기
        result = subprocess.run(
            ['manage-bde', '-on', drive, '-UsedSpaceOnly', '-SkipHardwareTest'],
            capture_output=True,
            text=True,
            timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        # TPM 없이 실패할 경우 복구 키 기반 암호화 시도
        if result.returncode != 0:
            # 복구 비밀번호 생성 및 암호화 시도
            result = subprocess.run(
                ['manage-bde', '-on', drive, '-RecoveryPassword', '-UsedSpaceOnly', '-SkipHardwareTest'],
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

        if result.returncode != 0:
            error_msg = result.stderr or result.stdout
            return ManageBdeResult(
                success=False,
                error=f"manage-bde -on failed: {error_msg}"
            )

        logger.info(f"BitLocker encryption started on {drive} (running in background)")

        if not wait_for_completion:
            return ManageBdeResult(
                success=True,
                message="encryption_started",
                protection_status="On"
            )

        # 완료까지 대기
        while True:
            time.sleep(check_interval)
            status = get_bitlocker_status(drive)

            if not status.success:
                return status

            logger.info(f"BitLocker encryption progress: {status.percentage:.1f}%")

            if progress_callback:
                progress_callback(status.percentage, f"암호화 진행 중: {status.percentage:.1f}%")

            if status.message == "fully_encrypted" or status.percentage >= 100.0:
                logger.info(f"BitLocker encryption completed on {drive}")
                if progress_callback:
                    progress_callback(100.0, "암호화 완료")
                return ManageBdeResult(
                    success=True,
                    message="encryption_completed",
                    percentage=100.0,
                    protection_status="On"
                )

    except subprocess.TimeoutExpired:
        return ManageBdeResult(success=False, error="manage-bde timeout")
    except Exception as e:
        return ManageBdeResult(success=False, error=str(e))
