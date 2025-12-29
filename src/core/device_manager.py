# -*- coding: utf-8 -*-
"""
Unified Device Manager

디바이스 통합 관리자 - Windows 물리 디스크, Android, iOS, E01 이미지를
하나의 인터페이스로 통합 관리합니다.

Features:
    - 실시간 디바이스 감지 (폴링 기반)
    - 복수 디바이스 선택
    - Qt 시그널을 통한 UI 연동
    - 디바이스 유형별 메타데이터 관리
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, List, Dict, Any, Set
from datetime import datetime
import logging

from PyQt6.QtCore import QObject, pyqtSignal, QTimer

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class DeviceType(Enum):
    """디바이스 유형"""
    WINDOWS_PHYSICAL_DISK = auto()
    WINDOWS_PARTITION = auto()
    E01_IMAGE = auto()
    RAW_IMAGE = auto()
    ANDROID_DEVICE = auto()
    IOS_BACKUP = auto()


class DeviceStatus(Enum):
    """디바이스 상태"""
    CONNECTED = auto()      # 연결됨
    DISCONNECTED = auto()   # 연결 해제됨
    READY = auto()          # 수집 준비됨
    BUSY = auto()           # 수집 중
    ERROR = auto()          # 오류 상태
    LOCKED = auto()         # BitLocker/암호화


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class UnifiedDeviceInfo:
    """
    통합 디바이스 정보

    모든 디바이스 유형(물리 디스크, Android, iOS, E01)을
    하나의 구조로 표현합니다.
    """
    device_id: str                      # 고유 식별자
    device_type: DeviceType             # 디바이스 유형
    display_name: str                   # 사용자 표시명
    status: DeviceStatus = DeviceStatus.DISCONNECTED

    # 공통 메타데이터
    size_bytes: int = 0
    size_display: str = ""              # "256 GB"
    connection_time: Optional[datetime] = None

    # 유형별 추가 메타데이터 (유연성을 위해 dict 사용)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # 선택 상태
    is_selected: bool = False
    is_selectable: bool = True
    selection_disabled_reason: str = ""

    def __post_init__(self):
        """크기 표시 문자열 자동 생성"""
        if self.size_bytes > 0 and not self.size_display:
            self.size_display = self._format_size(self.size_bytes)

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """바이트 크기를 사람이 읽기 쉬운 형태로 변환"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"

    @property
    def is_mobile(self) -> bool:
        """모바일 디바이스인지 확인"""
        return self.device_type in (DeviceType.ANDROID_DEVICE, DeviceType.IOS_BACKUP)

    @property
    def is_image(self) -> bool:
        """이미지 파일인지 확인"""
        return self.device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE)

    @property
    def requires_admin(self) -> bool:
        """관리자 권한이 필요한지 확인"""
        return self.device_type == DeviceType.WINDOWS_PHYSICAL_DISK


# =============================================================================
# Device Manager
# =============================================================================

class UnifiedDeviceManager(QObject):
    """
    통합 디바이스 관리자

    여러 유형의 디바이스를 통합 관리하고 실시간 감지를 지원합니다.
    Qt 시그널을 통해 UI와 연동됩니다.

    Usage:
        manager = UnifiedDeviceManager()
        manager.device_added.connect(on_device_added)
        manager.start_monitoring()

        # 디바이스 선택
        manager.select_device('physical_disk_0', True)

        # 선택된 디바이스 가져오기
        selected = manager.get_selected_devices()
    """

    # Qt 시그널
    device_added = pyqtSignal(object)       # UnifiedDeviceInfo
    device_removed = pyqtSignal(str)         # device_id
    device_updated = pyqtSignal(object)      # UnifiedDeviceInfo
    selection_changed = pyqtSignal()
    scan_started = pyqtSignal()
    scan_completed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        self._devices: Dict[str, UnifiedDeviceInfo] = {}
        self._selected_devices: Set[str] = set()
        self._enumerators: Dict[str, 'BaseDeviceEnumerator'] = {}

        # 폴링 타이머
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_devices)

        # 초기화 플래그
        self._initialized = False

    def register_enumerator(self, name: str, enumerator: 'BaseDeviceEnumerator'):
        """
        디바이스 열거자 등록

        Args:
            name: 열거자 이름 (예: 'windows', 'android')
            enumerator: BaseDeviceEnumerator 구현체
        """
        self._enumerators[name] = enumerator
        logger.info(f"Registered device enumerator: {name}")

    def start_monitoring(self, poll_interval_ms: int = 2000):
        """
        디바이스 모니터링 시작

        Args:
            poll_interval_ms: 폴링 간격 (밀리초)
        """
        if not self._enumerators:
            logger.warning("No device enumerators registered")
            return

        logger.info(f"Starting device monitoring (interval: {poll_interval_ms}ms)")
        self._poll_timer.start(poll_interval_ms)
        self._poll_devices()  # 즉시 첫 스캔
        self._initialized = True

    def stop_monitoring(self):
        """디바이스 모니터링 중지"""
        self._poll_timer.stop()
        logger.info("Device monitoring stopped")

    def _poll_devices(self):
        """모든 열거자에서 디바이스 폴링"""
        self.scan_started.emit()
        current_ids = set()

        for name, enumerator in self._enumerators.items():
            try:
                for device in enumerator.enumerate():
                    current_ids.add(device.device_id)

                    if device.device_id not in self._devices:
                        # 새 디바이스 발견
                        self._devices[device.device_id] = device
                        logger.info(f"Device added: {device.display_name} ({device.device_type.name})")
                        self.device_added.emit(device)
                    else:
                        # 기존 디바이스 상태 변경 확인
                        existing = self._devices[device.device_id]
                        if existing.status != device.status:
                            self._devices[device.device_id] = device
                            logger.info(f"Device updated: {device.display_name} -> {device.status.name}")
                            self.device_updated.emit(device)

            except Exception as e:
                logger.error(f"Error polling {name} enumerator: {e}")

        # 제거된 디바이스 확인 (이미지 파일 제외 - 수동 추가이므로)
        removed = set(self._devices.keys()) - current_ids
        for device_id in removed:
            device = self._devices.get(device_id)
            if device and not device.is_image:
                del self._devices[device_id]
                self._selected_devices.discard(device_id)
                logger.info(f"Device removed: {device_id}")
                self.device_removed.emit(device_id)

        self.scan_completed.emit()

    def refresh(self):
        """디바이스 목록 새로고침 (수동)"""
        self._poll_devices()

    # =========================================================================
    # Device Access
    # =========================================================================

    def get_all_devices(self) -> List[UnifiedDeviceInfo]:
        """모든 디바이스 목록 반환"""
        return list(self._devices.values())

    def get_device(self, device_id: str) -> Optional[UnifiedDeviceInfo]:
        """특정 디바이스 가져오기"""
        return self._devices.get(device_id)

    def get_devices_by_type(self, device_type: DeviceType) -> List[UnifiedDeviceInfo]:
        """유형별 디바이스 필터링"""
        return [d for d in self._devices.values() if d.device_type == device_type]

    def get_selected_devices(self) -> List[UnifiedDeviceInfo]:
        """선택된 디바이스 목록 반환"""
        return [
            self._devices[id]
            for id in self._selected_devices
            if id in self._devices
        ]

    # =========================================================================
    # Selection Management
    # =========================================================================

    def select_device(self, device_id: str, selected: bool = True):
        """
        디바이스 선택/해제

        Args:
            device_id: 디바이스 ID
            selected: True=선택, False=해제
        """
        if device_id not in self._devices:
            logger.warning(f"Device not found: {device_id}")
            return

        device = self._devices[device_id]
        if not device.is_selectable:
            logger.warning(f"Device not selectable: {device_id} ({device.selection_disabled_reason})")
            return

        device.is_selected = selected
        if selected:
            self._selected_devices.add(device_id)
        else:
            self._selected_devices.discard(device_id)

        self.selection_changed.emit()

    def select_all(self, device_type: Optional[DeviceType] = None):
        """
        전체 선택

        Args:
            device_type: 특정 유형만 선택 (None이면 전체)
        """
        for device in self._devices.values():
            if device.is_selectable:
                if device_type is None or device.device_type == device_type:
                    self.select_device(device.device_id, True)

    def deselect_all(self):
        """전체 선택 해제"""
        for device_id in list(self._selected_devices):
            self.select_device(device_id, False)

    def toggle_selection(self, device_id: str):
        """선택 토글"""
        if device_id in self._devices:
            current = self._devices[device_id].is_selected
            self.select_device(device_id, not current)

    @property
    def selected_count(self) -> int:
        """선택된 디바이스 수"""
        return len(self._selected_devices)

    @property
    def total_count(self) -> int:
        """전체 디바이스 수"""
        return len(self._devices)

    # =========================================================================
    # Image File Management
    # =========================================================================

    def add_image_file(self, file_path: str) -> Optional[UnifiedDeviceInfo]:
        """
        E01/RAW 이미지 파일 수동 추가

        Args:
            file_path: 이미지 파일 경로

        Returns:
            추가된 디바이스 정보 (실패 시 None)
        """
        if 'images' not in self._enumerators:
            logger.error("ForensicImageEnumerator not registered")
            return None

        try:
            enumerator = self._enumerators['images']
            device = enumerator.register_image(file_path)

            self._devices[device.device_id] = device
            logger.info(f"Image file added: {device.display_name}")
            self.device_added.emit(device)

            return device

        except Exception as e:
            logger.error(f"Failed to add image file: {e}")
            return None

    def remove_image_file(self, device_id: str):
        """
        이미지 파일 제거

        Args:
            device_id: 제거할 이미지 디바이스 ID
        """
        if device_id in self._devices:
            device = self._devices[device_id]
            if device.is_image:
                del self._devices[device_id]
                self._selected_devices.discard(device_id)
                logger.info(f"Image file removed: {device_id}")
                self.device_removed.emit(device_id)
