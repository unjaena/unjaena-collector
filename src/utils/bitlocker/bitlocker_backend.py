# -*- coding: utf-8 -*-
"""
BitLocker Backend - BitLocker decryption backend using dissect.fve

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

# Dynamic loading of dissect.fve module
_bde_class = None
_fve_available = False


def _load_dissect_fve():
    """Attempt to load dissect.fve module"""
    global _bde_class, _fve_available
    if _bde_class is not None:
        return _fve_available

    try:
        from dissect.fve.bde import BDE
        _bde_class = BDE
        _fve_available = True
        logger.info("dissect.fve loaded successfully")
    except ImportError as e:
        _bde_class = None
        _fve_available = False
        logger.warning(f"dissect.fve not available: {e}. Install with: pip install dissect.fve")

    return _fve_available


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
    Can be passed to dissect.fve BDE()
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

    @property
    def size(self) -> int:
        """Size property for compatibility with dissect.fve BitlockerStream"""
        return self._size

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
    Wraps dissect.fve BDE volume with UnifiedDiskReader interface
    Allows decrypted volume to be used with existing forensic accessors
    """

    def __init__(self, source: Union[str, PartitionSliceReader, BinaryIO]):
        super().__init__()

        if not _load_dissect_fve():
            raise BitLockerError(
                "dissect.fve is not installed. "
                "Install with: pip install dissect.fve"
            )

        self._source = source
        self._bde = None
        self._stream = None  # BitlockerStream (decrypted, seekable)
        self._source_fh = None  # file handle we opened (to close later)
        self._is_unlocked = False
        self._volume_info: Optional[BitLockerVolumeInfo] = None
        self._key_type_used: Optional[BitLockerKeyType] = None
        self._pending_key = None  # (key_type, value) tuple

        self._open_volume()

    def _open_volume(self) -> None:
        try:
            if isinstance(self._source, str):
                self._source_fh = open(self._source, 'rb')
                try:
                    self._bde = _bde_class(self._source_fh)
                except Exception:
                    self._source_fh.close()
                    self._source_fh = None
                    raise
                logger.info(f"Opened BitLocker volume from path: {self._source}")
            else:
                self._bde = _bde_class(self._source)
                logger.info("Opened BitLocker volume from file object")

            self._is_open = True
            self._load_volume_info()

        except Exception as e:
            raise BitLockerError(f"Failed to open BitLocker volume: {e}")

    def _load_volume_info(self) -> None:
        try:
            encryption_method = self._get_encryption_method_str()
            volume_id = ""
            protector_count = 0
            is_locked = True

            # Best-effort metadata extraction from dissect.fve
            try:
                if hasattr(self._bde, 'volume_identifier'):
                    volume_id = str(self._bde.volume_identifier or "")
            except Exception:
                pass

            try:
                if hasattr(self._bde, 'protectors'):
                    protector_count = len(list(self._bde.protectors))
            except Exception:
                pass

            self._volume_info = BitLockerVolumeInfo(
                encryption_method=encryption_method,
                volume_identifier=volume_id,
                key_protector_count=protector_count,
                is_locked=is_locked
            )

            # Size is only available after unlock (via BitlockerStream)
            self._disk_size = 0

        except Exception as e:
            logger.warning(f"Failed to load volume info: {e}")
            self._volume_info = BitLockerVolumeInfo()

    def _get_encryption_method_str(self) -> str:
        try:
            if hasattr(self._bde, 'encryption_method'):
                method = self._bde.encryption_method
                if method is not None:
                    return str(method)
            return "Unknown"
        except Exception:
            return "Unknown"

    # ========== Key Setting Methods ==========

    def set_recovery_password(self, recovery_password: str) -> None:
        if not self._bde:
            raise BitLockerError("Volume not opened")

        cleaned = recovery_password.replace("-", "").replace(" ", "")
        if len(cleaned) != 48 or not cleaned.isdigit():
            logger.warning(f"Recovery password format may be invalid: {len(cleaned)} chars")

        self._pending_key = ('recovery', recovery_password)
        self._key_type_used = BitLockerKeyType.RECOVERY_PASSWORD
        logger.info("Recovery password set (pending unlock)")

    def set_password(self, password: str) -> None:
        if not self._bde:
            raise BitLockerError("Volume not opened")

        self._pending_key = ('password', password)
        self._key_type_used = BitLockerKeyType.PASSWORD
        logger.info("Password set (pending unlock)")

    def read_startup_key(self, bek_path: str) -> None:
        if not self._bde:
            raise BitLockerError("Volume not opened")

        self._pending_key = ('bek', bek_path)
        self._key_type_used = BitLockerKeyType.BEK_FILE
        logger.info(f"Startup key path set: {bek_path} (pending unlock)")

    # ========== Unlock ==========

    def unlock(self) -> bool:
        """Unlock the BitLocker volume with the previously set key.

        Returns True on success.
        Raises BitLockerError on failure with the actual error message from dissect.fve.
        """
        if not self._bde:
            raise BitLockerError("Volume not opened")

        if not self._pending_key:
            raise BitLockerError(
                "No key set. Call set_recovery_password(), set_password(), "
                "or read_startup_key() first."
            )

        try:
            key_type, value = self._pending_key
            logger.info(f"Attempting unlock with key_type='{key_type}'")

            if key_type == 'recovery':
                self._bde.unlock_with_recovery_password(value)
            elif key_type == 'password':
                self._bde.unlock_with_passphrase(value)
            elif key_type == 'bek':
                with open(value, 'rb') as f:
                    self._bde.unlock_with_bek(f)
            else:
                raise BitLockerError(f"Unknown internal key type: {key_type}")

            logger.info("Key accepted, opening decrypted stream...")

            # BDE.open() returns BitlockerStream (AlignedStream with seek/read)
            self._stream = self._bde.open()
            if not self._stream:
                raise BitLockerError("Failed to open decrypted stream (bde.open() returned None)")

            self._is_unlocked = True
            logger.info(f"BitLocker volume unlocked using {self._key_type_used.value}")

            # Update size after unlock
            try:
                self._disk_size = self._stream.size
            except Exception:
                pass

            return True

        except ValueError as e:
            # dissect.fve raises ValueError for key validation/decryption failures
            logger.error(f"BitLocker unlock failed: {e}")
            self._is_unlocked = False
            raise BitLockerError(str(e))
        except Exception as e:
            logger.error(f"BitLocker unlock failed: {e}")
            self._is_unlocked = False
            raise BitLockerError(f"Unlock failed: {e}")

    def is_locked(self) -> bool:
        return not self._is_unlocked

    # ========== UnifiedDiskReader Interface Implementation ==========

    def read(self, offset: int, size: int) -> bytes:
        if not self._stream:
            if not self._is_unlocked:
                raise BitLockerError(
                    "Volume is locked. Call unlock() with valid credentials first."
                )
            raise BitLockerError("Decrypted stream not available")

        try:
            self._stream.seek(offset)
            return self._stream.read(size)
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
        if self._stream:
            try:
                if hasattr(self._stream, 'close'):
                    self._stream.close()
            except Exception as e:
                logger.warning(f"Error closing BitLocker stream: {e}")
            finally:
                self._stream = None

        if self._bde:
            try:
                if hasattr(self._bde, 'close'):
                    self._bde.close()
            except Exception as e:
                logger.warning(f"Error closing BDE volume: {e}")
            finally:
                self._bde = None

        if self._source_fh:
            try:
                self._source_fh.close()
            except Exception:
                pass
            self._source_fh = None

        self._is_open = False
        self._is_unlocked = False

    # ========== Additional Methods ==========

    def get_volume_info(self) -> BitLockerVolumeInfo:
        return self._volume_info or BitLockerVolumeInfo()

    def get_key_protectors(self) -> list:
        if not self._bde:
            return []

        protectors = []
        try:
            if hasattr(self._bde, 'protectors'):
                for i, protector in enumerate(self._bde.protectors):
                    try:
                        protectors.append({
                            'index': i,
                            'identifier': str(getattr(protector, 'identifier', None)),
                            'type': self._get_protector_type(protector)
                        })
                    except Exception as e:
                        protectors.append({'index': i, 'error': str(e)})
        except Exception as e:
            logger.warning(f"Failed to get key protectors: {e}")

        return protectors

    def _get_protector_type(self, protector) -> str:
        try:
            if hasattr(protector, 'type'):
                ptype = protector.type
                if hasattr(ptype, 'value'):
                    ptype = ptype.value
                types = {
                    0x0000: "Clear Key",
                    0x0100: "TPM",
                    0x0200: "External Key",
                    0x0500: "TPM + PIN",
                    0x0800: "Recovery Password",
                    0x2000: "Password",
                }
                return types.get(ptype, f"Unknown ({ptype})")
            return "Unknown"
        except Exception:
            return "Unknown"

    @property
    def is_unlocked(self) -> bool:
        return self._is_unlocked

    @property
    def key_type_used(self) -> Optional[BitLockerKeyType]:
        return self._key_type_used


def is_pybde_available() -> bool:
    """Check if decryption library (dissect.fve) is available"""
    return _load_dissect_fve()


# Backward compatibility alias
def is_fve_available() -> bool:
    """Check if dissect.fve is available"""
    return _load_dissect_fve()
