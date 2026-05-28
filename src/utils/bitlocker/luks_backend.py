# -*- coding: utf-8 -*-
"""
LUKS Backend - LUKS encrypted volume backend using dissect.fve

Supports LUKS1 and LUKS2 encrypted volumes.
"""

from typing import Optional, Union, BinaryIO
from dataclasses import dataclass
import logging

from .unified_disk_reader import (
    UnifiedDiskReader, DiskInfo, DiskSourceType,
    DiskError
)

logger = logging.getLogger(__name__)

LUKS_SIGNATURE = b'LUKS\xba\xbe'  # 6 bytes at offset 0


def is_luks_partition(data: bytes) -> bool:
    """Check if partition starts with LUKS signature"""
    return len(data) >= 6 and data[:6] == LUKS_SIGNATURE


@dataclass
class LUKSVolumeInfo:
    """LUKS volume information"""
    version: int = 0  # 1 or 2
    cipher: str = ""
    uuid: str = ""
    is_locked: bool = True


class LUKSBackend(UnifiedDiskReader):
    """
    LUKS encrypted volume decryption backend

    Uses dissect.fve to handle LUKS1/LUKS2 volumes.
    After unlock, provides file-like read access to decrypted data.
    """

    def __init__(self, source: Union[str, BinaryIO]):
        super().__init__()

        self._source = source
        self._luks = None
        self._source_fh = None
        self._is_unlocked = False
        self._volume_info: Optional[LUKSVolumeInfo] = None

        self._open_volume()

    def _open_volume(self) -> None:
        try:
            from dissect.fve.luks import LUKS
        except ImportError:
            raise DiskError(
                "dissect.fve is not installed. "
                "Install with: pip install dissect.fve"
            )

        try:
            if isinstance(self._source, str):
                self._source_fh = open(self._source, 'rb')
                try:
                    self._luks = LUKS(self._source_fh)
                except Exception:
                    self._source_fh.close()
                    self._source_fh = None
                    raise
                logger.info(f"Opened LUKS volume from path: {self._source}")
            else:
                self._luks = LUKS(self._source)
                logger.info("Opened LUKS volume from file object")

            self._is_open = True
            self._load_volume_info()

        except Exception as e:
            raise DiskError(f"Failed to open LUKS volume: {e}")

    def _load_volume_info(self) -> None:
        try:
            version = 0
            cipher = ""
            uuid = ""

            try:
                if hasattr(self._luks, 'version'):
                    version = self._luks.version
            except Exception:
                pass

            try:
                if hasattr(self._luks, 'cipher'):
                    cipher = str(self._luks.cipher)
            except Exception:
                pass

            try:
                if hasattr(self._luks, 'uuid'):
                    uuid = str(self._luks.uuid)
            except Exception:
                pass

            self._volume_info = LUKSVolumeInfo(
                version=version,
                cipher=cipher,
                uuid=uuid,
                is_locked=True
            )

            try:
                self._disk_size = self._luks.size
            except Exception:
                self._disk_size = 0

        except Exception as e:
            logger.warning(f"Failed to load LUKS volume info: {e}")
            self._volume_info = LUKSVolumeInfo()

    def unlock_with_passphrase(self, passphrase: str) -> bool:
        """Unlock LUKS volume with passphrase"""
        if not self._luks:
            raise DiskError("LUKS volume not opened")

        try:
            self._luks.unlock_with_passphrase(passphrase)
            self._is_unlocked = True
            logger.info("LUKS volume unlocked with passphrase")

            try:
                self._disk_size = self._luks.size
            except Exception:
                pass

            if self._volume_info:
                self._volume_info.is_locked = False

            return True

        except ValueError as e:
            logger.error(f"LUKS unlock failed: {e}")
            self._is_unlocked = False
            raise DiskError(str(e))
        except Exception as e:
            logger.error(f"LUKS unlock failed: {e}")
            self._is_unlocked = False
            raise DiskError(f"LUKS unlock failed: {e}")

    def is_locked(self) -> bool:
        return not self._is_unlocked

    # ========== UnifiedDiskReader Interface ==========

    def read(self, offset: int, size: int) -> bytes:
        if not self._luks:
            raise DiskError("LUKS volume not opened")

        if not self._is_unlocked:
            raise DiskError(
                "Volume is locked. Call unlock_with_passphrase() first."
            )

        try:
            self._luks.seek(offset)
            return self._luks.read(size)
        except Exception as e:
            raise DiskError(f"Failed to read decrypted LUKS data: {e}")

    def get_size(self) -> int:
        return self._disk_size

    def get_disk_info(self) -> DiskInfo:
        source_path = self._source if isinstance(self._source, str) else "file_object"
        return DiskInfo(
            source_type=DiskSourceType.RAW_IMAGE,
            total_size=self._disk_size,
            sector_size=512,
            source_path=source_path,
            is_readonly=True,
            model="LUKS Decrypted Volume",
            serial=self._volume_info.uuid if self._volume_info else ""
        )

    def close(self) -> None:
        if self._luks:
            try:
                if hasattr(self._luks, 'close'):
                    self._luks.close()
            except Exception as e:
                logger.warning(f"Error closing LUKS volume: {e}")
            finally:
                self._luks = None

        if self._source_fh:
            try:
                self._source_fh.close()
            except Exception:
                pass
            self._source_fh = None

        self._is_open = False
        self._is_unlocked = False

    # ========== Additional Methods ==========

    def get_volume_info(self) -> LUKSVolumeInfo:
        return self._volume_info or LUKSVolumeInfo()

    @property
    def is_unlocked(self) -> bool:
        return self._is_unlocked
