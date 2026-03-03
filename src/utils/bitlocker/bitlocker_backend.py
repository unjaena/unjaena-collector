# -*- coding: utf-8 -*-
"""
BitLocker Backend - BitLocker decryption backend using pybde

Supported Key Types:
- Recovery Password (48-digit number: 123456-234567-...)
- Password (regular password)
- Start-up Key (.BEK file)

Not Supported:
- TPM (Trusted Platform Module) - hardware dependent
"""

from typing import Optional, Union, BinaryIO, Any
from dataclasses import dataclass
from enum import Enum
import logging
import io

from .unified_disk_reader import (
    UnifiedDiskReader, DiskInfo, DiskSourceType,
    BitLockerError
)

logger = logging.getLogger(__name__)

# Dynamic loading of pybde module
_pybde = None
_pybde_available = False


def _load_pybde():
    """Attempt to load pybde module"""
    global _pybde, _pybde_available
    if _pybde is not None:
        return _pybde_available

    try:
        import pybde
        _pybde = pybde
        _pybde_available = True
        logger.info("pybde (libbde-python) loaded successfully")
    except ImportError as e:
        _pybde = None
        _pybde_available = False
        logger.warning(f"pybde not available: {e}. Install with: pip install libbde-python")

    return _pybde_available


class BitLockerKeyType(Enum):
    """BitLocker key type"""
    RECOVERY_PASSWORD = "recovery_password"
    PASSWORD = "password"
    BEK_FILE = "bek_file"
    CLEAR_KEY = "clear_key"


@dataclass
class BitLockerVolumeInfo:
    """BitLocker volume information"""
    encryption_method: str = ""
    volume_identifier: str = ""
    creation_time: str = ""
    description: str = ""
    key_protector_count: int = 0
    is_locked: bool = True


class PartitionSliceReader:
    """
    Wraps a specific partition area of the disk backend as a file-like object
    Can be passed to pybde.open_file_object()
    """

    def __init__(self, backend: UnifiedDiskReader, offset: int, size: int):
        self._backend = backend
        self._offset = offset
        self._size = size
        self._position = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = self._size - self._position

        actual_size = min(size, self._size - self._position)
        if actual_size <= 0:
            return b''

        data = self._backend.read(self._offset + self._position, actual_size)
        self._position += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._position = offset
        elif whence == 1:
            self._position += offset
        elif whence == 2:
            self._position = self._size + offset

        self._position = max(0, min(self._position, self._size))
        return self._position

    def tell(self) -> int:
        return self._position

    def get_size(self) -> int:
        return self._size

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False


class BitLockerBackend(UnifiedDiskReader):
    """
    Wraps pybde volume with UnifiedDiskReader interface
    Allows decrypted volume to be used with existing forensic accessors
    """

    def __init__(self, source: Union[str, PartitionSliceReader, BinaryIO]):
        super().__init__()

        if not _load_pybde():
            raise BitLockerError(
                "pybde (libbde-python) is not installed. "
                "Install with: pip install libbde-python"
            )

        self._source = source
        self._pybde_volume = None
        self._is_unlocked = False
        self._volume_info: Optional[BitLockerVolumeInfo] = None
        self._key_type_used: Optional[BitLockerKeyType] = None

        self._open_volume()

    def _open_volume(self) -> None:
        try:
            self._pybde_volume = _pybde.volume()

            if isinstance(self._source, str):
                self._pybde_volume.open(self._source)
                logger.info(f"Opened BitLocker volume from path: {self._source}")
            else:
                self._pybde_volume.open_file_object(self._source)
                logger.info("Opened BitLocker volume from file object")

            self._is_open = True
            self._load_volume_info()

        except Exception as e:
            raise BitLockerError(f"Failed to open BitLocker volume: {e}")

    def _load_volume_info(self) -> None:
        try:
            self._volume_info = BitLockerVolumeInfo(
                encryption_method=self._get_encryption_method_str(),
                volume_identifier=self._pybde_volume.get_volume_identifier() or "",
                key_protector_count=self._pybde_volume.get_number_of_key_protectors(),
                is_locked=self._pybde_volume.is_locked()
            )
            self._disk_size = self._pybde_volume.get_size()

        except Exception as e:
            logger.warning(f"Failed to load volume info: {e}")
            self._volume_info = BitLockerVolumeInfo()

    def _get_encryption_method_str(self) -> str:
        try:
            method = self._pybde_volume.get_encryption_method()
            methods = {
                0: "None",
                1: "AES-128-CBC + Diffuser",
                2: "AES-256-CBC + Diffuser",
                3: "AES-128-CBC",
                4: "AES-256-CBC",
                5: "AES-128-XTS",
                6: "AES-256-XTS",
            }
            return methods.get(method, f"Unknown ({method})")
        except:
            return "Unknown"

    # ========== Key Setting Methods ==========

    def set_recovery_password(self, recovery_password: str) -> None:
        if not self._pybde_volume:
            raise BitLockerError("Volume not opened")

        cleaned = recovery_password.replace("-", "").replace(" ", "")
        if len(cleaned) != 48 or not cleaned.isdigit():
            logger.warning(f"Recovery password format may be invalid: {len(cleaned)} chars")

        try:
            self._pybde_volume.set_recovery_password(recovery_password)
            self._key_type_used = BitLockerKeyType.RECOVERY_PASSWORD
            logger.info("Recovery password set")
        except Exception as e:
            raise BitLockerError(f"Failed to set recovery password: {e}")

    def set_password(self, password: str) -> None:
        if not self._pybde_volume:
            raise BitLockerError("Volume not opened")

        try:
            self._pybde_volume.set_password(password)
            self._key_type_used = BitLockerKeyType.PASSWORD
            logger.info("Password set")
        except Exception as e:
            raise BitLockerError(f"Failed to set password: {e}")

    def read_startup_key(self, bek_path: str) -> None:
        if not self._pybde_volume:
            raise BitLockerError("Volume not opened")

        try:
            self._pybde_volume.read_startup_key(bek_path)
            self._key_type_used = BitLockerKeyType.BEK_FILE
            logger.info(f"Startup key loaded from: {bek_path}")
        except Exception as e:
            raise BitLockerError(f"Failed to read startup key: {e}")

    # ========== Unlock ==========

    def unlock(self) -> bool:
        if not self._pybde_volume:
            raise BitLockerError("Volume not opened")

        if not self._key_type_used:
            raise BitLockerError(
                "No key set. Call set_recovery_password(), set_password(), "
                "or read_startup_key() first."
            )

        try:
            self._pybde_volume.unlock()
            self._is_unlocked = not self._pybde_volume.is_locked()

            if self._is_unlocked:
                logger.info(f"BitLocker volume unlocked using {self._key_type_used.value}")
                self._disk_size = self._pybde_volume.get_size()
            else:
                logger.warning("unlock() called but volume is still locked")

            return self._is_unlocked

        except Exception as e:
            logger.error(f"BitLocker unlock failed: {e}")
            self._is_unlocked = False
            return False

    def is_locked(self) -> bool:
        if not self._pybde_volume:
            return True
        return self._pybde_volume.is_locked()

    # ========== UnifiedDiskReader Interface Implementation ==========

    def read(self, offset: int, size: int) -> bytes:
        if not self._pybde_volume:
            raise BitLockerError("Volume not opened")

        if self._pybde_volume.is_locked():
            raise BitLockerError(
                "Volume is locked. Call unlock() with valid credentials first."
            )

        try:
            return self._pybde_volume.read_buffer_at_offset(size, offset)
        except Exception as e:
            raise BitLockerError(f"Failed to read decrypted data: {e}")

    def get_size(self) -> int:
        return self._disk_size

    def get_disk_info(self) -> DiskInfo:
        source_path = self._source if isinstance(self._source, str) else "file_object"

        return DiskInfo(
            source_type=DiskSourceType.PHYSICAL_DISK,
            total_size=self._disk_size,
            sector_size=512,
            source_path=source_path,
            is_readonly=True,
            model="BitLocker Decrypted Volume",
            serial=self._volume_info.volume_identifier if self._volume_info else ""
        )

    def close(self) -> None:
        if self._pybde_volume:
            try:
                self._pybde_volume.close()
            except Exception as e:
                logger.warning(f"Error closing pybde volume: {e}")
            finally:
                self._pybde_volume = None
                self._is_open = False
                self._is_unlocked = False

    # ========== Additional Methods ==========

    def get_volume_info(self) -> BitLockerVolumeInfo:
        return self._volume_info or BitLockerVolumeInfo()

    def get_key_protectors(self) -> list:
        if not self._pybde_volume:
            return []

        protectors = []
        try:
            count = self._pybde_volume.get_number_of_key_protectors()
            for i in range(count):
                try:
                    protector = self._pybde_volume.get_key_protector(i)
                    protectors.append({
                        'index': i,
                        'identifier': protector.get_identifier() if hasattr(protector, 'get_identifier') else None,
                        'type': self._get_protector_type(protector)
                    })
                except Exception as e:
                    protectors.append({'index': i, 'error': str(e)})
        except Exception as e:
            logger.warning(f"Failed to get key protectors: {e}")

        return protectors

    def _get_protector_type(self, protector) -> str:
        try:
            ptype = protector.get_type() if hasattr(protector, 'get_type') else None
            types = {
                0x0000: "Clear Key",
                0x0100: "TPM",
                0x0200: "External Key",
                0x0500: "TPM + PIN",
                0x0800: "Recovery Password",
                0x2000: "Password",
            }
            return types.get(ptype, f"Unknown ({ptype})")
        except:
            return "Unknown"

    @property
    def is_unlocked(self) -> bool:
        return self._is_unlocked

    @property
    def key_type_used(self) -> Optional[BitLockerKeyType]:
        return self._key_type_used


def is_pybde_available() -> bool:
    """Check if pybde is available"""
    return _load_pybde()
