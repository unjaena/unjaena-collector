# -*- coding: utf-8 -*-
"""
Device Enumerators

다양한 디바이스 유형에 대한 열거자 구현.
각 열거자는 BaseDeviceEnumerator 인터페이스를 구현합니다.

Enumerators:
    - WindowsDiskEnumerator: Windows 물리 디스크 (WMI 기반)
    - AndroidDeviceEnumerator: Android 기기 (ADB 기반)
    - iOSBackupEnumerator: iOS 백업 파일
    - ForensicImageEnumerator: E01/RAW 이미지 파일
"""

import sys
import logging
import hashlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from .device_manager import (
    UnifiedDeviceInfo,
    DeviceType,
    DeviceStatus
)

logger = logging.getLogger(__name__)


# =============================================================================
# Base Class
# =============================================================================

class BaseDeviceEnumerator(ABC):
    """
    디바이스 열거자 기본 클래스

    모든 디바이스 열거자는 이 클래스를 상속받아 구현합니다.
    """

    @abstractmethod
    def enumerate(self) -> List[UnifiedDeviceInfo]:
        """
        현재 사용 가능한 디바이스 목록 반환

        Returns:
            디바이스 정보 목록
        """
        pass

    @abstractmethod
    def supports_realtime(self) -> bool:
        """
        실시간 감지 지원 여부

        Returns:
            True면 실시간 감지 가능
        """
        pass

    def is_available(self) -> bool:
        """
        이 열거자가 현재 환경에서 사용 가능한지 확인

        Returns:
            사용 가능 여부
        """
        return True


# =============================================================================
# Windows Disk Enumerator
# =============================================================================

class WindowsDiskEnumerator(BaseDeviceEnumerator):
    """
    Windows 물리 디스크 열거자

    WMI를 통해 시스템의 물리 디스크를 열거합니다.
    관리자 권한이 필요할 수 있습니다.
    """

    def __init__(self):
        self._wmi_available = False
        self._wmi = None

        if sys.platform == 'win32':
            try:
                import wmi
                self._wmi = wmi.WMI()
                self._wmi_available = True
                logger.info("WMI initialized successfully")
            except ImportError:
                logger.warning("WMI module not available. Install with: pip install wmi")
            except Exception as e:
                logger.error(f"WMI initialization failed: {e}")

    def is_available(self) -> bool:
        return self._wmi_available

    def supports_realtime(self) -> bool:
        return True  # WMI 이벤트를 통한 실시간 감지 가능

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        if not self._wmi_available:
            return []

        devices = []

        try:
            for disk in self._wmi.Win32_DiskDrive():
                try:
                    size = int(disk.Size or 0)
                    device = UnifiedDeviceInfo(
                        device_id=f"physical_disk_{disk.Index}",
                        device_type=DeviceType.WINDOWS_PHYSICAL_DISK,
                        display_name=f"{disk.Model or f'Disk {disk.Index}'} ({disk.Index})",
                        status=DeviceStatus.READY,
                        size_bytes=size,
                        connection_time=datetime.now(),
                        metadata={
                            'drive_number': disk.Index,
                            'model': disk.Model or 'Unknown',
                            'serial': disk.SerialNumber,
                            'interface_type': disk.InterfaceType,
                            'partitions': disk.Partitions or 0,
                            'media_type': disk.MediaType,
                            'device_id': disk.DeviceID,
                        }
                    )
                    devices.append(device)

                except Exception as e:
                    logger.warning(f"Error processing disk {disk.Index}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Failed to enumerate Windows disks: {e}")

        return devices


# =============================================================================
# Android Device Enumerator
# =============================================================================

class AndroidDeviceEnumerator(BaseDeviceEnumerator):
    """
    Android 디바이스 열거자

    기존 ADBDeviceMonitor를 래핑하여 통합 인터페이스를 제공합니다.
    """

    def __init__(self):
        self._adb_available = False
        self._monitor = None

        try:
            from collectors.android_collector import ADBDeviceMonitor, ADB_AVAILABLE
            if ADB_AVAILABLE:
                self._adb_available = True
                self._monitor = ADBDeviceMonitor()
                logger.info("ADB device monitor initialized")
            else:
                logger.warning("ADB not available")
        except ImportError:
            logger.warning("Android collector module not available")
        except Exception as e:
            logger.error(f"Android collector initialization failed: {e}")

    def is_available(self) -> bool:
        return self._adb_available

    def supports_realtime(self) -> bool:
        return True  # ADB 폴링 기반 실시간 감지

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        if not self._adb_available or not self._monitor:
            return []

        devices = []

        try:
            # ADBDeviceMonitor에서 연결된 기기 목록 가져오기
            connected = self._monitor.get_connected_devices()

            for dev_info in connected:
                # 선택 가능 여부 결정
                is_selectable = True
                disabled_reason = ""

                if not dev_info.rooted:
                    # 루팅되지 않은 기기는 제한된 수집만 가능
                    disabled_reason = "Limited collection (device not rooted)"

                device = UnifiedDeviceInfo(
                    device_id=f"android_{dev_info.serial}",
                    device_type=DeviceType.ANDROID_DEVICE,
                    display_name=f"{dev_info.manufacturer} {dev_info.model}",
                    status=DeviceStatus.READY,
                    size_bytes=dev_info.storage_available,
                    connection_time=datetime.now(),
                    is_selectable=is_selectable,
                    selection_disabled_reason=disabled_reason,
                    metadata={
                        'serial': dev_info.serial,
                        'model': dev_info.model,
                        'manufacturer': dev_info.manufacturer,
                        'android_version': dev_info.android_version,
                        'sdk_version': dev_info.sdk_version,
                        'usb_debugging': dev_info.usb_debugging,
                        'rooted': dev_info.rooted,
                        'storage_available': dev_info.storage_available,
                    }
                )
                devices.append(device)

        except Exception as e:
            logger.error(f"Failed to enumerate Android devices: {e}")

        return devices


# =============================================================================
# iOS Backup Enumerator
# =============================================================================

class iOSBackupEnumerator(BaseDeviceEnumerator):
    """
    iOS 백업 열거자

    iTunes/Finder 백업 디렉토리를 스캔하여 iOS 백업을 찾습니다.
    """

    def __init__(self):
        self._available = False

        try:
            from collectors.ios_collector import find_ios_backups
            self._find_backups = find_ios_backups
            self._available = True
            logger.info("iOS backup enumerator initialized")
        except ImportError:
            logger.warning("iOS collector module not available")
        except Exception as e:
            logger.error(f"iOS collector initialization failed: {e}")

    def is_available(self) -> bool:
        return self._available

    def supports_realtime(self) -> bool:
        return False  # 백업 디렉토리는 실시간 변경이 드묾

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        if not self._available:
            return []

        devices = []

        try:
            backups = self._find_backups()

            for backup in backups:
                # 암호화된 백업은 선택 불가
                is_selectable = not backup.encrypted
                disabled_reason = ""

                if backup.encrypted:
                    disabled_reason = "Encrypted backup (password required)"
                    status = DeviceStatus.LOCKED
                else:
                    status = DeviceStatus.READY

                size_bytes = int(backup.size_mb * 1024 * 1024) if hasattr(backup, 'size_mb') else 0

                device = UnifiedDeviceInfo(
                    device_id=f"ios_backup_{backup.device_id}",
                    device_type=DeviceType.IOS_BACKUP,
                    display_name=f"{backup.device_name} (iOS {backup.ios_version})",
                    status=status,
                    size_bytes=size_bytes,
                    is_selectable=is_selectable,
                    selection_disabled_reason=disabled_reason,
                    metadata={
                        'device_id': backup.device_id,
                        'device_name': backup.device_name,
                        'ios_version': backup.ios_version,
                        'backup_date': backup.backup_date.isoformat() if hasattr(backup, 'backup_date') else None,
                        'encrypted': backup.encrypted,
                        'path': str(backup.path),
                    }
                )
                devices.append(device)

        except Exception as e:
            logger.error(f"Failed to enumerate iOS backups: {e}")

        return devices


# =============================================================================
# Forensic Image Enumerator
# =============================================================================

class ForensicImageEnumerator(BaseDeviceEnumerator):
    """
    포렌식 이미지 열거자

    사용자가 수동으로 추가한 E01/RAW 이미지 파일을 관리합니다.
    """

    # 지원하는 확장자
    E01_EXTENSIONS = {'.e01', '.ex01', '.s01', '.l01'}
    RAW_EXTENSIONS = {'.dd', '.raw', '.img', '.bin'}

    def __init__(self):
        self._registered_images: Dict[str, UnifiedDeviceInfo] = {}
        logger.info("Forensic image enumerator initialized")

    def is_available(self) -> bool:
        return True  # 항상 사용 가능

    def supports_realtime(self) -> bool:
        return False  # 수동 추가만 지원

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        """등록된 이미지 파일 목록 반환"""
        return list(self._registered_images.values())

    def register_image(self, file_path: str) -> UnifiedDeviceInfo:
        """
        E01/RAW 이미지 파일 등록

        Args:
            file_path: 이미지 파일 경로

        Returns:
            생성된 디바이스 정보

        Raises:
            FileNotFoundError: 파일이 없는 경우
            ValueError: 지원하지 않는 확장자인 경우
        """
        path = Path(file_path).resolve()

        # 파일 존재 확인
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        # 경로 순회 방지
        if '..' in str(path):
            raise ValueError("Path traversal detected")

        ext = path.suffix.lower()
        all_extensions = self.E01_EXTENSIONS | self.RAW_EXTENSIONS

        if ext not in all_extensions:
            raise ValueError(f"Unsupported file type: {ext}. Supported: {all_extensions}")

        # 디바이스 유형 결정
        if ext in self.E01_EXTENSIONS:
            device_type = DeviceType.E01_IMAGE
        else:
            device_type = DeviceType.RAW_IMAGE

        # 파일 크기
        size_bytes = path.stat().st_size

        # E01 이미지인 경우 실제 디스크 크기 가져오기 시도
        if device_type == DeviceType.E01_IMAGE:
            size_bytes = self._get_e01_disk_size(path) or size_bytes

        # 고유 ID 생성
        device_id = f"image_{hashlib.md5(str(path).encode()).hexdigest()[:12]}"

        device = UnifiedDeviceInfo(
            device_id=device_id,
            device_type=device_type,
            display_name=path.name,
            status=DeviceStatus.READY,
            size_bytes=size_bytes,
            connection_time=datetime.now(),
            metadata={
                'file_path': str(path),
                'extension': ext,
                'segments': self._find_e01_segments(path) if device_type == DeviceType.E01_IMAGE else [],
            }
        )

        self._registered_images[device_id] = device
        logger.info(f"Registered forensic image: {path.name} ({device_type.name})")

        return device

    def unregister_image(self, device_id: str) -> bool:
        """
        이미지 파일 등록 해제

        Args:
            device_id: 제거할 이미지 ID

        Returns:
            성공 여부
        """
        if device_id in self._registered_images:
            del self._registered_images[device_id]
            logger.info(f"Unregistered forensic image: {device_id}")
            return True
        return False

    def _get_e01_disk_size(self, path: Path) -> Optional[int]:
        """E01 이미지에서 실제 디스크 크기 가져오기"""
        try:
            from collectors.forensic_disk import E01DiskBackend
            with E01DiskBackend(str(path)) as backend:
                disk_info = backend.get_disk_info()
                return disk_info.total_size
        except Exception as e:
            logger.debug(f"Could not get E01 disk size: {e}")
            return None

    def _find_e01_segments(self, first_segment: Path) -> List[str]:
        """E01 세그먼트 파일 찾기"""
        segments = [str(first_segment)]

        # E01 -> E02, E03, ... 또는 Ex01 -> Ex02, Ex03, ...
        base = first_segment.stem
        parent = first_segment.parent

        # E01 형식 (E01, E02, ... E99, EAA, EAB, ...)
        if first_segment.suffix.lower() in ('.e01', '.ex01'):
            for i in range(2, 100):
                suffix = f".E{i:02d}" if first_segment.suffix.startswith('.E') else f".e{i:02d}"
                segment = parent / f"{base}{suffix}"
                if segment.exists():
                    segments.append(str(segment))
                else:
                    break

        return segments


# =============================================================================
# Factory Function
# =============================================================================

def create_default_enumerators() -> Dict[str, BaseDeviceEnumerator]:
    """
    기본 열거자 세트 생성

    Returns:
        이름 -> 열거자 매핑
    """
    enumerators = {}

    # Windows 디스크 (Windows에서만)
    if sys.platform == 'win32':
        windows = WindowsDiskEnumerator()
        if windows.is_available():
            enumerators['windows'] = windows

    # Android
    android = AndroidDeviceEnumerator()
    if android.is_available():
        enumerators['android'] = android

    # iOS 백업
    ios = iOSBackupEnumerator()
    if ios.is_available():
        enumerators['ios'] = ios

    # 포렌식 이미지 (항상 사용 가능)
    enumerators['images'] = ForensicImageEnumerator()

    logger.info(f"Created {len(enumerators)} device enumerators: {list(enumerators.keys())}")
    return enumerators
