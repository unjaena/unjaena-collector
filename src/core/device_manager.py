# -*- coding: utf-8 -*-
"""
Unified Device Manager

Manages Windows physical disks, Android, iOS, and E01 images
through a unified interface.

Features:
    - Real-time device detection (polling-based)
    - Multiple device selection
    - UI integration via Qt signals
    - Device type-specific metadata management
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
    """Device type"""
    WINDOWS_PHYSICAL_DISK = auto()
    WINDOWS_PARTITION = auto()
    E01_IMAGE = auto()
    RAW_IMAGE = auto()
    ANDROID_DEVICE = auto()
    IOS_BACKUP = auto()
    IOS_DEVICE = auto()  # iOS device via USB direct connection


class DeviceStatus(Enum):
    """Device status"""
    CONNECTED = auto()      # Connected
    DISCONNECTED = auto()   # Disconnected
    READY = auto()          # Ready for collection
    BUSY = auto()           # Collection in progress
    ERROR = auto()          # Error state
    LOCKED = auto()         # BitLocker/encrypted


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class UnifiedDeviceInfo:
    """
    Unified device information

    Represents all device types (physical disk, Android, iOS, E01)
    in a single structure.
    """
    device_id: str                      # Unique identifier
    device_type: DeviceType             # Device type
    display_name: str                   # User display name
    status: DeviceStatus = DeviceStatus.DISCONNECTED

    # Common metadata
    size_bytes: int = 0
    size_display: str = ""              # "256 GB"
    connection_time: Optional[datetime] = None

    # Type-specific additional metadata (dict for flexibility)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Selection state
    is_selected: bool = False
    is_selectable: bool = True
    selection_disabled_reason: str = ""

    def __post_init__(self):
        """Auto-generate size display string"""
        if self.size_bytes > 0 and not self.size_display:
            self.size_display = self._format_size(self.size_bytes)

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Convert byte size to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"

    @property
    def is_mobile(self) -> bool:
        """Check if mobile device"""
        return self.device_type in (DeviceType.ANDROID_DEVICE, DeviceType.IOS_BACKUP)

    @property
    def is_image(self) -> bool:
        """Check if image file"""
        return self.device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE)

    @property
    def requires_admin(self) -> bool:
        """Check if admin privileges required"""
        return self.device_type == DeviceType.WINDOWS_PHYSICAL_DISK


# =============================================================================
# Device Manager
# =============================================================================

class UnifiedDeviceManager(QObject):
    """
    Unified device manager

    Manages multiple device types and supports real-time detection.
    Integrates with UI via Qt signals.

    Usage:
        manager = UnifiedDeviceManager()
        manager.device_added.connect(on_device_added)
        manager.start_monitoring()

        # Select device
        manager.select_device('physical_disk_0', True)

        # Get selected devices
        selected = manager.get_selected_devices()
    """

    # Qt signals
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

        # Polling timer
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_devices)

        # Initialization flag
        self._initialized = False

    def register_enumerator(self, name: str, enumerator: 'BaseDeviceEnumerator'):
        """
        Register device enumerator

        Args:
            name: Enumerator name (e.g., 'windows', 'android')
            enumerator: BaseDeviceEnumerator implementation
        """
        self._enumerators[name] = enumerator
        logger.info(f"Registered device enumerator: {name}")

    def start_monitoring(self, poll_interval_ms: int = 2000):
        """
        Start device monitoring

        Args:
            poll_interval_ms: Polling interval (milliseconds)
        """
        if not self._enumerators:
            logger.warning("No device enumerators registered")
            return

        logger.info(f"Starting device monitoring (interval: {poll_interval_ms}ms)")
        self._poll_timer.start(poll_interval_ms)
        self._poll_devices()  # Immediate first scan
        self._initialized = True

    def stop_monitoring(self):
        """Stop device monitoring"""
        self._poll_timer.stop()
        logger.info("Device monitoring stopped")

    def _poll_devices(self):
        """Poll devices from all enumerators"""
        self.scan_started.emit()
        current_ids = set()

        for name, enumerator in self._enumerators.items():
            try:
                for device in enumerator.enumerate():
                    current_ids.add(device.device_id)

                    if device.device_id not in self._devices:
                        # New device found
                        self._devices[device.device_id] = device
                        logger.info(f"Device added: {device.display_name} ({device.device_type.name})")
                        self.device_added.emit(device)
                    else:
                        # Check for existing device status change
                        existing = self._devices[device.device_id]
                        if existing.status != device.status:
                            self._devices[device.device_id] = device
                            logger.info(f"Device updated: {device.display_name} -> {device.status.name}")
                            self.device_updated.emit(device)

            except Exception as e:
                logger.error(f"Error polling {name} enumerator: {e}")

        # Check for removed devices (exclude image files - manually added)
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
        """Refresh device list (manual)"""
        self._poll_devices()

    # =========================================================================
    # Device Access
    # =========================================================================

    def get_all_devices(self) -> List[UnifiedDeviceInfo]:
        """Return all device list"""
        return list(self._devices.values())

    def get_device(self, device_id: str) -> Optional[UnifiedDeviceInfo]:
        """Get specific device"""
        return self._devices.get(device_id)

    def get_devices_by_type(self, device_type: DeviceType) -> List[UnifiedDeviceInfo]:
        """Filter devices by type"""
        return [d for d in self._devices.values() if d.device_type == device_type]

    def get_selected_devices(self) -> List[UnifiedDeviceInfo]:
        """Return selected device list"""
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
        Select/deselect device

        Args:
            device_id: Device ID
            selected: True=select, False=deselect
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
        Select all

        Args:
            device_type: Select specific type only (None for all)
        """
        for device in self._devices.values():
            if device.is_selectable:
                if device_type is None or device.device_type == device_type:
                    self.select_device(device.device_id, True)

    def deselect_all(self):
        """Deselect all"""
        for device_id in list(self._selected_devices):
            self.select_device(device_id, False)

    def toggle_selection(self, device_id: str):
        """Toggle selection"""
        if device_id in self._devices:
            current = self._devices[device_id].is_selected
            self.select_device(device_id, not current)

    @property
    def selected_count(self) -> int:
        """Number of selected devices"""
        return len(self._selected_devices)

    @property
    def total_count(self) -> int:
        """Total number of devices"""
        return len(self._devices)

    # =========================================================================
    # Image File Management
    # =========================================================================

    def add_image_file(self, file_path: str) -> Optional[UnifiedDeviceInfo]:
        """
        Manually add E01/RAW image file

        Args:
            file_path: Image file path

        Returns:
            Added device info (None on failure)
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
        Remove image file

        Args:
            device_id: Image device ID to remove
        """
        if device_id in self._devices:
            device = self._devices[device_id]
            if device.is_image:
                del self._devices[device_id]
                self._selected_devices.discard(device_id)
                logger.info(f"Image file removed: {device_id}")
                self.device_removed.emit(device_id)
