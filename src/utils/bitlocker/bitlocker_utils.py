# -*- coding: utf-8 -*-
"""
BitLocker Utilities - BitLocker volume detection and utility functions

Utilities for detecting and handling BitLocker encrypted volumes in the collector tool.
"""

import struct
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class BitLockerVolumeDetectionResult:
    """BitLocker volume detection result"""
    is_encrypted: bool = False
    partition_index: int = 0
    partition_offset: int = 0
    partition_size: int = 0
    encryption_method: str = ""
    drive_letter: str = ""
    error: Optional[str] = None


def detect_bitlocker_on_system_drive() -> BitLockerVolumeDetectionResult:
    """
    Detect BitLocker encryption on the system drive (typically C:)

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
        # Check BitLocker status via WMI
        result = _check_bitlocker_via_wmi()
        if result:
            return result

        # Fall back to direct disk check if WMI fails
        return _check_bitlocker_direct()

    except Exception as e:
        logger.error(f"BitLocker detection failed: {e}")
        return BitLockerVolumeDetectionResult(
            is_encrypted=False,
            error=str(e)
        )


def _check_bitlocker_via_wmi() -> Optional[BitLockerVolumeDetectionResult]:
    """Check BitLocker status via WMI"""
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
    """Get encryption method from WMI volume"""
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
    """Detect BitLocker by reading physical disk directly"""
    try:
        from .disk_backends import PhysicalDiskBackend

        # Check PhysicalDrive0 (system disk)
        backend = PhysicalDiskBackend(0)

        try:
            # Read MBR
            mbr = backend.read(0, 512)
            if len(mbr) < 512:
                return BitLockerVolumeDetectionResult(is_encrypted=False)

            # Verify MBR signature
            signature = struct.unpack('<H', mbr[510:512])[0]
            if signature != 0xAA55:
                return BitLockerVolumeDetectionResult(
                    is_encrypted=False,
                    error="Invalid MBR signature"
                )

            # Check for GPT protective MBR (partition type 0xEE = GPT Protective)
            # Check the type of the first partition entry
            first_partition_type = mbr[446 + 4]  # Type of the first partition
            is_gpt = first_partition_type == 0xEE

            if is_gpt:
                # Handle GPT disk
                logger.debug("GPT disk detected, checking GPT partitions")
                return _check_bitlocker_gpt(backend)

            # Check MBR partitions
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

                # Check for BitLocker signature in VBR
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
    """Detect BitLocker on GPT disk"""
    try:
        # GPT header (LBA 1)
        gpt_header = backend.read(512, 512)

        if gpt_header[:8] != b'EFI PART':
            logger.debug("Not a valid GPT header")
            return BitLockerVolumeDetectionResult(is_encrypted=False)

        logger.debug("Valid GPT header found")

        # Partition entry start LBA
        entries_lba = struct.unpack('<Q', gpt_header[72:80])[0]
        num_entries = struct.unpack('<I', gpt_header[80:84])[0]
        entry_size = struct.unpack('<I', gpt_header[84:88])[0]

        logger.debug(f"GPT: {num_entries} partition entries, size={entry_size}")

        # Read partition entries
        entries_offset = entries_lba * 512
        entries_data = backend.read(entries_offset, num_entries * entry_size)

        partitions_found = 0
        for i in range(min(num_entries, 128)):  # Check up to 128 entries
            entry_offset = i * entry_size
            entry = entries_data[entry_offset:entry_offset + entry_size]

            # Partition type GUID (offset 0-16)
            type_guid = entry[:16]

            # Skip empty entries
            if type_guid == b'\x00' * 16:
                continue

            partitions_found += 1

            # Partition offset and size
            first_lba = struct.unpack('<Q', entry[32:40])[0]
            last_lba = struct.unpack('<Q', entry[40:48])[0]
            partition_offset = first_lba * 512
            partition_size = (last_lba - first_lba + 1) * 512

            # Check for BitLocker signature in VBR
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
    """Check if VBR is BitLocker encrypted"""
    if len(vbr) < 512:
        return False

    # BitLocker signature: "-FVE-FS-" at offset 3
    return vbr[3:11] == b'-FVE-FS-'


def detect_bitlocker_partitions(drive_number: int = 0) -> List[Dict[str, Any]]:
    """
    Detect all BitLocker encrypted partitions on a specified physical drive

    Args:
        drive_number: Physical drive number

    Returns:
        List of BitLocker partition information
    """
    from .disk_backends import PhysicalDiskBackend

    partitions = []

    try:
        backend = PhysicalDiskBackend(drive_number)

        try:
            # Read MBR
            mbr = backend.read(0, 512)

            # Verify MBR signature
            signature = struct.unpack('<H', mbr[510:512])[0]

            if signature == 0xAA55:
                # MBR partition table
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
                # Handle GPT disk (simplified)
                logger.info("GPT disk detected - scanning partitions")

        finally:
            backend.close()

    except Exception as e:
        logger.error(f"Failed to detect BitLocker partitions: {e}")

    return partitions


def _detect_filesystem(vbr: bytes) -> str:
    """Detect filesystem from VBR"""
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
    """Check if pybde (libbde-python) is installed"""
    try:
        import pybde
        return True
    except ImportError:
        return False


def format_recovery_password(raw_input: str) -> str:
    """
    Convert recovery key input to standard format

    Input: "123456234567345678..." or "123456-234567-345678-..."
    Output: "123456-234567-345678-456789-567890-678901-789012-890123"
    """
    # Extract digits only
    digits = ''.join(c for c in raw_input if c.isdigit())

    if len(digits) != 48:
        raise ValueError(
            f"Recovery password must be 48 digits, got {len(digits)}"
        )

    # Group into 6-digit chunks
    groups = [digits[i:i+6] for i in range(0, 48, 6)]
    return '-'.join(groups)


def validate_recovery_password(password: str) -> bool:
    """Validate recovery key format"""
    try:
        format_recovery_password(password)
        return True
    except ValueError:
        return False


# =============================================================================
# manage-bde based BitLocker auto unlock/re-encryption
# =============================================================================

@dataclass
class ManageBdeResult:
    """manage-bde execution result"""
    success: bool = False
    message: str = ""
    percentage: float = 0.0  # Encryption/decryption progress percentage
    protection_status: str = ""  # On, Off, Unknown
    error: Optional[str] = None


def check_admin_privileges() -> bool:
    """Check for administrator privileges"""
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
    Check BitLocker status using manage-bde

    Args:
        drive: Drive letter (e.g., "C:")

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

        # Parse protection status
        protection_status = "Unknown"
        if "Protection On" in output:
            protection_status = "On"
        elif "Protection Off" in output:
            protection_status = "Off"

        # Parse encryption percentage
        percentage = 0.0
        percentage_match = re.search(r'(\d+(?:\.\d+)?)\s*%', output)
        if percentage_match:
            percentage = float(percentage_match.group(1))

        # Check encryption status
        is_encrypted = "Fully Encrypted" in output
        is_decrypted = "Fully Decrypted" in output or percentage == 0.0

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
    Disable BitLocker encryption (manage-bde -off)

    Args:
        drive: Drive letter (e.g., "C:")
        progress_callback: Progress callback function (percentage: float, message: str)
        wait_for_completion: Whether to wait until completion
        check_interval: Status check interval (seconds)

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

    # Check current status
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
        # Start BitLocker decryption
        logger.info(f"Starting BitLocker decryption on {drive}")
        if progress_callback:
            progress_callback(0.0, f"Starting BitLocker decryption: {drive}")

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

        # Wait until completion
        while True:
            time.sleep(check_interval)
            status = get_bitlocker_status(drive)

            if not status.success:
                return status

            remaining = 100.0 - status.percentage if status.percentage > 0 else 0.0
            logger.info(f"BitLocker decryption progress: {remaining:.1f}% remaining")

            if progress_callback:
                progress_callback(remaining, f"Decryption in progress: {remaining:.1f}% remaining")

            if status.message == "fully_decrypted" or status.percentage == 0.0:
                logger.info(f"BitLocker decryption completed on {drive}")
                if progress_callback:
                    progress_callback(100.0, "Decryption completed")
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
    Enable BitLocker encryption (manage-bde -on)

    Args:
        drive: Drive letter (e.g., "C:")
        progress_callback: Progress callback function (percentage: float, message: str)
        wait_for_completion: Whether to wait until completion (default: False - background encryption)
        check_interval: Status check interval (seconds)

    Returns:
        ManageBdeResult

    Note:
        Re-encryption will automatically use the key if TPM is present.
        Additional configuration may be required if TPM is not available or a recovery key is needed.
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

    # Check current status
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
        # Start BitLocker encryption (using TPM)
        logger.info(f"Starting BitLocker encryption on {drive}")
        if progress_callback:
            progress_callback(0.0, f"Starting BitLocker encryption: {drive}")

        # -UsedSpaceOnly: Encrypt only used space (faster)
        # -SkipHardwareTest: Skip hardware test
        result = subprocess.run(
            ['manage-bde', '-on', drive, '-UsedSpaceOnly', '-SkipHardwareTest'],
            capture_output=True,
            text=True,
            timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        # If failed without TPM, try recovery key based encryption
        if result.returncode != 0:
            # Generate recovery password and attempt encryption
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

        # Wait until completion
        while True:
            time.sleep(check_interval)
            status = get_bitlocker_status(drive)

            if not status.success:
                return status

            logger.info(f"BitLocker encryption progress: {status.percentage:.1f}%")

            if progress_callback:
                progress_callback(status.percentage, f"Encryption in progress: {status.percentage:.1f}%")

            if status.message == "fully_encrypted" or status.percentage >= 100.0:
                logger.info(f"BitLocker encryption completed on {drive}")
                if progress_callback:
                    progress_callback(100.0, "Encryption completed")
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
