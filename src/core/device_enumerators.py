# -*- coding: utf-8 -*-
"""
Device Enumerators

Enumerator implementations for various device types.
Each enumerator implements the BaseDeviceEnumerator interface.

Enumerators:
    - WindowsDiskEnumerator: Windows physical disks (WMI-based)
    - AndroidDeviceEnumerator: Android devices (ADB-based)
    - iOSBackupEnumerator: iOS backup files
    - iOSDeviceEnumerator: iOS USB direct connection (pymobiledevice3-based)
    - ForensicImageEnumerator: E01/RAW image files
"""

import sys
import logging
import hashlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Dict
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
    Device enumerator base class

    All device enumerators inherit from this class.
    """

    @abstractmethod
    def enumerate(self) -> List[UnifiedDeviceInfo]:
        """
        Return currently available device list

        Returns:
            List of device information
        """
        pass

    @abstractmethod
    def supports_realtime(self) -> bool:
        """
        Whether real-time detection is supported

        Returns:
            True if real-time detection is possible
        """
        pass

    def is_available(self) -> bool:
        """
        Check if this enumerator is available in the current environment

        Returns:
            Availability status
        """
        return True


# =============================================================================
# Windows Disk Enumerator
# =============================================================================

class WindowsDiskEnumerator(BaseDeviceEnumerator):
    """
    Windows physical disk enumerator

    Enumerates physical disks on the system via WMI.
    Administrator privileges may be required.
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
        return True  # Real-time detection via WMI events

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        if not self._wmi_available:
            return []

        devices = []

        try:
            # [2026-02-15] Build disk → drive letter mapping via WMI
            # Use Win32_LogicalDisk → associators to find physical disk
            disk_to_volumes = {}  # disk_index -> list of drive letters
            try:
                # Method: For each logical disk, trace back to physical disk
                for logical_disk in self._wmi.Win32_LogicalDisk():
                    try:
                        drive_letter = logical_disk.DeviceID  # e.g., "C:", "D:"
                        if not drive_letter:
                            continue
                        letter = drive_letter.rstrip(':')

                        # Get partitions associated with this logical disk
                        for partition in logical_disk.associators(
                            wmi_result_class="Win32_DiskPartition"
                        ):
                            # Get disk drives associated with this partition
                            for disk_drive in partition.associators(
                                wmi_result_class="Win32_DiskDrive"
                            ):
                                disk_index = disk_drive.Index
                                if disk_index is not None:
                                    if disk_index not in disk_to_volumes:
                                        disk_to_volumes[disk_index] = []
                                    if letter not in disk_to_volumes[disk_index]:
                                        disk_to_volumes[disk_index].append(letter)
                    except Exception as e:
                        logger.debug(f"Volume mapping for {logical_disk.DeviceID}: {e}")
                        continue

                logger.debug(f"Disk to volumes mapping: {disk_to_volumes}")
            except Exception as e:
                logger.warning(f"Volume mapping failed (will use fallback): {e}")

            for disk in self._wmi.Win32_DiskDrive():
                try:
                    size = int(disk.Size or 0)
                    disk_index = disk.Index

                    # Get volumes for this disk
                    volumes = disk_to_volumes.get(disk_index, [])
                    # Use first volume as primary, or 'C' as fallback
                    primary_volume = volumes[0] if volumes else None

                    device = UnifiedDeviceInfo(
                        device_id=f"physical_disk_{disk_index}",
                        device_type=DeviceType.WINDOWS_PHYSICAL_DISK,
                        display_name=f"{disk.Model or f'Disk {disk_index}'} ({disk_index})",
                        status=DeviceStatus.READY,
                        size_bytes=size,
                        connection_time=datetime.now(),
                        metadata={
                            'drive_number': disk_index,
                            'model': disk.Model or 'Unknown',
                            'serial': disk.SerialNumber,
                            'interface_type': disk.InterfaceType,
                            'partitions': disk.Partitions or 0,
                            'media_type': disk.MediaType,
                            'device_id': disk.DeviceID,
                            'volume': primary_volume,          # [2026-02-15] Primary drive letter
                            'all_volumes': volumes,            # [2026-02-15] All drive letters on this disk
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
    Android device enumerator

    Wraps existing ADBDeviceMonitor to provide unified interface.
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
            logger.debug("Android collector module not available (ADB not installed)")
        except Exception as e:
            logger.error(f"Android collector initialization failed: {e}")

    def is_available(self) -> bool:
        return self._adb_available

    def supports_realtime(self) -> bool:
        return True  # Real-time detection via ADB polling

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        if not self._adb_available or not self._monitor:
            return []

        devices = []

        try:
            # Get connected device list from ADBDeviceMonitor
            connected = self._monitor.get_connected_devices()

            for dev_info in connected:
                # Determine selectability
                is_selectable = True
                disabled_reason = ""

                if not dev_info.rooted:
                    # Non-rooted devices have limited collection
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
    iOS backup enumerator

    Scans iTunes/Finder backup directory to find iOS backups.
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
        return False  # Backup directory changes are rare

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        if not self._available:
            return []

        devices = []

        try:
            backups = self._find_backups()

            for backup in backups:
                # Encrypted backups are selectable (password dialog will handle)
                is_selectable = True
                disabled_reason = ""

                if backup.encrypted:
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
# iOS Device Enumerator (USB Direct Connection)
# =============================================================================

class iOSDeviceEnumerator(BaseDeviceEnumerator):
    """
    iOS device USB direct connection enumerator

    Enumerates USB-connected iOS devices via pymobiledevice3.
    """

    def __init__(self):
        self._available = False

        try:
            from collectors.ios_collector import PYMOBILEDEVICE3_AVAILABLE
            self._available = PYMOBILEDEVICE3_AVAILABLE
            if self._available:
                logger.info("iOS device enumerator initialized (pymobiledevice3)")
            else:
                logger.warning("pymobiledevice3 not available")
        except ImportError:
            logger.warning("iOS collector module not available")
        except Exception as e:
            logger.error(f"iOS device enumerator initialization failed: {e}")

    def is_available(self) -> bool:
        return self._available

    def supports_realtime(self) -> bool:
        return True  # USB connection detection supported

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        if not self._available:
            return []

        devices = []

        try:
            from pymobiledevice3.usbmux import list_devices
            from pymobiledevice3.lockdown import create_using_usbmux

            connected = list_devices()

            for device in connected:
                try:
                    lockdown = create_using_usbmux(serial=device.serial)
                    all_values = lockdown.all_values

                    device_info = UnifiedDeviceInfo(
                        device_id=f"ios_device_{device.serial}",
                        device_type=DeviceType.IOS_DEVICE,
                        display_name=f"{all_values.get('DeviceName', 'iOS Device')} ({all_values.get('ProductType', 'Unknown')})",
                        status=DeviceStatus.READY,
                        size_bytes=0,  # iOS doesn't easily report storage
                        connection_time=datetime.now(),
                        metadata={
                            'udid': device.serial,
                            'device_name': all_values.get('DeviceName', 'Unknown'),
                            'product_type': all_values.get('ProductType', 'Unknown'),
                            'ios_version': all_values.get('ProductVersion', 'Unknown'),
                            'serial_number': all_values.get('SerialNumber', 'Unknown'),
                            'connection_type': 'USB',
                        }
                    )
                    devices.append(device_info)

                except Exception as e:
                    logger.warning(f"Error getting info for device {device.serial}: {e}")
                    # Still add the device but with limited info
                    device_info = UnifiedDeviceInfo(
                        device_id=f"ios_device_{device.serial}",
                        device_type=DeviceType.IOS_DEVICE,
                        display_name=f"iOS Device ({device.serial[:8]}...)",
                        status=DeviceStatus.LOCKED,
                        size_bytes=0,
                        connection_time=datetime.now(),
                        is_selectable=False,
                        selection_disabled_reason="Device not paired - trust this computer on device",
                        metadata={
                            'udid': device.serial,
                            'connection_type': 'USB',
                        }
                    )
                    devices.append(device_info)

        except Exception as e:
            logger.error(f"Failed to enumerate iOS devices: {e}")

        return devices


# =============================================================================
# Android WiFi Device Enumerator
# =============================================================================

class AndroidWiFiDeviceEnumerator(BaseDeviceEnumerator):
    """
    Android device enumerator for WiFi ADB connections.
    Discovers Android devices accessible via ADB over TCP/IP.
    """

    def __init__(self):
        self._available = False
        try:
            from collectors.android_wifi_collector import wifi_adb_available
            self._available = wifi_adb_available()
        except ImportError:
            pass

    def is_available(self) -> bool:
        return self._available

    def supports_realtime(self) -> bool:
        return False  # Requires explicit scan

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        # Return empty list - WiFi devices are added manually by user
        # (scan initiated from GUI, not auto-detected)
        return []


# =============================================================================
# Android Hardware-Level Enumerator (EDL / MTK BROM)
# =============================================================================

class AndroidHardwareEnumerator(BaseDeviceEnumerator):
    """
    Android hardware-level device enumerator.
    Detects devices in EDL or MTK BROM mode via USB VID/PID.
    """

    # Qualcomm EDL USB identifiers
    QUALCOMM_EDL_VID = 0x05C6
    QUALCOMM_EDL_PID = 0x9008

    # MediaTek BROM USB identifiers
    MTK_BROM_VID = 0x0E8D
    MTK_BROM_PIDS = [0x0003, 0x2000, 0x0001]

    def __init__(self):
        self._usb_available = False
        try:
            import usb1
            self._usb_available = True
        except ImportError:
            try:
                import usb.core
                self._usb_available = True
            except ImportError:
                pass

    def is_available(self) -> bool:
        return self._usb_available

    def supports_realtime(self) -> bool:
        return False

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        devices = []

        try:
            import usb1
            with usb1.USBContext() as ctx:
                for dev in ctx.getDeviceIterator(skip_on_error=True):
                    vid = dev.getVendorID()
                    pid = dev.getProductID()

                    if vid == self.QUALCOMM_EDL_VID and pid == self.QUALCOMM_EDL_PID:
                        devices.append(UnifiedDeviceInfo(
                            device_id=f"edl_{vid:04x}_{pid:04x}_{dev.getBusNumber()}_{dev.getDeviceAddress()}",
                            device_type=DeviceType.ANDROID_EDL,
                            display_name="Qualcomm EDL Device",
                            status=DeviceStatus.READY,
                            metadata={
                                'vid': vid, 'pid': pid,
                                'bus': dev.getBusNumber(),
                                'address': dev.getDeviceAddress(),
                                'mode': 'edl',
                                'chipset': 'Qualcomm Snapdragon',
                            }
                        ))

                    elif vid == self.MTK_BROM_VID and pid in self.MTK_BROM_PIDS:
                        mode = 'preloader' if pid == 0x2000 else 'brom'
                        devices.append(UnifiedDeviceInfo(
                            device_id=f"mtk_{vid:04x}_{pid:04x}_{dev.getBusNumber()}_{dev.getDeviceAddress()}",
                            device_type=DeviceType.ANDROID_MTK_BROM,
                            display_name=f"MediaTek BROM Device ({mode})",
                            status=DeviceStatus.READY,
                            metadata={
                                'vid': vid, 'pid': pid,
                                'bus': dev.getBusNumber(),
                                'address': dev.getDeviceAddress(),
                                'mode': mode,
                                'chipset': 'MediaTek',
                            }
                        ))
        except Exception as e:
            logger.debug(f"USB enumeration error: {e}")

        return devices


# =============================================================================
# Forensic Image Enumerator
# =============================================================================

class ForensicImageEnumerator(BaseDeviceEnumerator):
    """
    Forensic image enumerator

    Manages E01/RAW image files manually added by user.
    """

    # Supported extensions
    E01_EXTENSIONS = {'.e01', '.ex01', '.s01', '.l01'}
    RAW_EXTENSIONS = {'.dd', '.raw', '.img', '.bin'}
    VMDK_EXTENSIONS = {'.vmdk'}
    VHD_EXTENSIONS = {'.vhd'}
    VHDX_EXTENSIONS = {'.vhdx'}
    QCOW2_EXTENSIONS = {'.qcow2'}
    VDI_EXTENSIONS = {'.vdi'}
    DMG_EXTENSIONS = {'.dmg'}

    def __init__(self):
        self._registered_images: Dict[str, UnifiedDeviceInfo] = {}
        logger.info("Forensic image enumerator initialized")

    def is_available(self) -> bool:
        return True  # Always available

    def supports_realtime(self) -> bool:
        return False  # Manual addition only

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        """Return registered image file list"""
        return list(self._registered_images.values())

    def register_image(self, file_path: str) -> UnifiedDeviceInfo:
        """
        Register E01/RAW image file

        Args:
            file_path: Image file path

        Returns:
            Created device information

        Raises:
            FileNotFoundError: File not found
            ValueError: Unsupported extension
        """
        # [SECURITY] Validate path traversal BEFORE resolving
        raw_path = str(file_path)
        if '..' in raw_path:
            raise ValueError("Path traversal detected")

        path = Path(file_path).resolve()

        # Check file exists
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        ext = path.suffix.lower()
        all_extensions = (
            self.E01_EXTENSIONS | self.RAW_EXTENSIONS |
            self.VMDK_EXTENSIONS | self.VHD_EXTENSIONS |
            self.VHDX_EXTENSIONS | self.QCOW2_EXTENSIONS |
            self.VDI_EXTENSIONS | self.DMG_EXTENSIONS
        )

        if ext not in all_extensions:
            raise ValueError(f"Unsupported file type: {ext}. Supported: {all_extensions}")

        # Determine device type
        if ext in self.E01_EXTENSIONS:
            device_type = DeviceType.E01_IMAGE
        elif ext in self.VMDK_EXTENSIONS:
            device_type = DeviceType.VMDK_IMAGE
        elif ext in self.VHD_EXTENSIONS:
            device_type = DeviceType.VHD_IMAGE
        elif ext in self.VHDX_EXTENSIONS:
            device_type = DeviceType.VHDX_IMAGE
        elif ext in self.QCOW2_EXTENSIONS:
            device_type = DeviceType.QCOW2_IMAGE
        elif ext in self.VDI_EXTENSIONS:
            device_type = DeviceType.VDI_IMAGE
        elif ext in self.DMG_EXTENSIONS:
            device_type = DeviceType.DMG_IMAGE
        else:
            device_type = DeviceType.RAW_IMAGE

        # File size
        size_bytes = path.stat().st_size

        # Try to get actual disk size for E01 images
        if device_type == DeviceType.E01_IMAGE:
            size_bytes = self._get_e01_disk_size(path) or size_bytes

        # Generate unique ID
        device_id = f"image_{hashlib.md5(str(path).encode()).hexdigest()[:12]}"

        # [New] OS type detection
        detected_os, filesystem_type = self._detect_image_os(path, device_type)

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
                'detected_os': detected_os,           # [New] windows/linux/macos/unknown
                'filesystem_type': filesystem_type,    # [New] NTFS/ext4/HFS+ etc.
            }
        )

        self._registered_images[device_id] = device
        logger.info(f"Registered forensic image: {path.name} ({device_type.name}) [OS: {detected_os}/{filesystem_type}]")

        return device

    def _detect_image_os(self, path: Path, device_type: DeviceType) -> tuple:
        """
        Detect OS type from E01/RAW image

        Args:
            path: Image file path
            device_type: Device type (E01_IMAGE or RAW_IMAGE)

        Returns:
            (detected_os, filesystem_type) tuple
            - detected_os: 'windows', 'linux', 'macos', 'unknown'
            - filesystem_type: 'NTFS', 'ext4', 'HFS+', 'Unknown' etc.
        """
        detected_os = 'unknown'
        filesystem_type = 'Unknown'

        try:
            from collectors.forensic_disk import ForensicDiskAccessor

            # Detect filesystem — auto_detect routes to correct backend by extension
            accessor = ForensicDiskAccessor.auto_detect(str(path))

            partitions = accessor.list_partitions()

            # [2026-02-05] FIX: NTFS를 FAT32보다 우선 (GPT의 EFI 파티션이 FAT32이므로)
            # 모든 파티션을 스캔하고, 우선순위: NTFS > ext4 > APFS > FAT32
            best_fs = None
            best_os = 'unknown'
            fs_priority = {'NTFS': 10, 'ext4': 9, 'ext3': 8, 'ext2': 7,
                           'APFS': 9, 'HFS+': 8, 'HFSX': 8, 'HFS': 7,
                           'exFAT': 5, 'FAT32': 3, 'FAT16': 2, 'FAT12': 1}

            for p in partitions:
                fs = p.filesystem
                priority = fs_priority.get(fs, 0)

                if priority > fs_priority.get(best_fs, 0):
                    best_fs = fs
                    if fs in ('NTFS', 'FAT32', 'exFAT', 'FAT16', 'FAT12'):
                        best_os = 'windows'
                    elif fs in ('ext2', 'ext3', 'ext4'):
                        best_os = 'linux'
                    elif fs in ('APFS', 'HFS+', 'HFS', 'HFSX'):
                        best_os = 'macos'

            if best_fs:
                detected_os = best_os
                filesystem_type = best_fs

            accessor.close()

        except Exception as e:
            logger.warning(f"OS detection failed for {path.name}: {e}")

        return detected_os, filesystem_type

    def unregister_image(self, device_id: str) -> bool:
        """
        Unregister image file

        Args:
            device_id: Image ID to remove

        Returns:
            Success status
        """
        if device_id in self._registered_images:
            del self._registered_images[device_id]
            logger.info(f"Unregistered forensic image: {device_id}")
            return True
        return False

    def _get_e01_disk_size(self, path: Path) -> Optional[int]:
        """Get actual disk size from E01 image"""
        try:
            from collectors.forensic_disk import E01DiskBackend
            with E01DiskBackend(str(path)) as backend:
                disk_info = backend.get_disk_info()
                return disk_info.total_size
        except Exception as e:
            logger.debug(f"Could not get E01 disk size: {e}")
            return None

    def _find_e01_segments(self, first_segment: Path) -> List[str]:
        """Find E01 segment files"""
        segments = [str(first_segment)]

        # E01 -> E02, E03, ... or Ex01 -> Ex02, Ex03, ...
        base = first_segment.stem
        parent = first_segment.parent

        # E01 format (E01, E02, ... E99, EAA, EAB, ...)
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
# macOS Local System Enumerator
# =============================================================================

class macOSLocalEnumerator(BaseDeviceEnumerator):
    """
    Local macOS system enumerator for live forensic collection.

    Detects the current macOS system and exposes it as a collectible device.
    Runs only on macOS (sys.platform == 'darwin').
    """

    def is_available(self) -> bool:
        return sys.platform == 'darwin'

    def supports_realtime(self) -> bool:
        return False  # Local system is always present

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        if sys.platform != 'darwin':
            return []

        try:
            import platform
            import shutil
            import os

            # Validate macOS filesystem layout
            required_dirs = ['/System', '/Library', '/Users']
            if not all(Path(d).is_dir() for d in required_dirs):
                return []

            # Read macOS version from SystemVersion.plist
            macos_version = ''
            product_name = 'macOS'
            try:
                import plistlib
                sv_path = Path('/System/Library/CoreServices/SystemVersion.plist')
                if sv_path.exists():
                    with open(sv_path, 'rb') as f:
                        sv = plistlib.load(f)
                    macos_version = sv.get('ProductVersion', '')
                    product_name = sv.get('ProductName', 'macOS')
            except Exception:
                pass

            # System info
            hostname = platform.node() or 'localhost'
            is_root = os.geteuid() == 0

            # Disk size
            disk = shutil.disk_usage('/')
            total_bytes = disk.total

            # Display name
            hw_model = ''
            try:
                import subprocess
                result = subprocess.run(
                    ['sysctl', '-n', 'hw.model'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    hw_model = result.stdout.strip()
            except Exception:
                pass

            display_parts = [hw_model or hostname]
            if macos_version:
                display_parts.append(f"{product_name} {macos_version}")
            display_name = ' - '.join(display_parts)

            device = UnifiedDeviceInfo(
                device_id='local_macos_system',
                device_type=DeviceType.MACOS_LOCAL_SYSTEM,
                display_name=display_name,
                status=DeviceStatus.READY,
                size_bytes=total_bytes,
                connection_time=datetime.now(),
                metadata={
                    'target_root': '/',
                    'macos_version': macos_version,
                    'hostname': hostname,
                    'is_root': is_root,
                    'detected_os': 'macos',
                    'hw_model': hw_model,
                },
                is_selectable=True,
            )

            if not is_root:
                logger.warning(
                    "macOS local collection: running without root. "
                    "Some artifacts (unified log, TCC.db, audit logs) will be inaccessible."
                )

            return [device]

        except Exception as e:
            logger.error(f"macOS local enumeration failed: {e}")
            return []


# =============================================================================
# Linux Local System Enumerator
# =============================================================================

class LinuxLocalEnumerator(BaseDeviceEnumerator):
    """
    Local Linux system enumerator for live forensic collection.

    Detects the current Linux system and exposes it as a collectible device.
    Runs only on Linux (sys.platform == 'linux').
    """

    def is_available(self) -> bool:
        return sys.platform.startswith('linux')

    def supports_realtime(self) -> bool:
        return False  # Local system is always present

    def enumerate(self) -> List[UnifiedDeviceInfo]:
        if not sys.platform.startswith('linux'):
            return []

        try:
            import platform
            import shutil
            import os

            # Validate Linux filesystem layout
            required_dirs = ['/etc', '/var', '/usr']
            if not all(Path(d).is_dir() for d in required_dirs):
                return []

            # Read distro info from /etc/os-release
            distro = 'Linux'
            distro_version = ''
            distro_id = ''
            try:
                os_release = Path('/etc/os-release')
                if os_release.exists():
                    data = {}
                    for line in os_release.read_text().splitlines():
                        if '=' in line:
                            key, _, val = line.partition('=')
                            data[key.strip()] = val.strip().strip('"')
                    distro = data.get('NAME', data.get('PRETTY_NAME', 'Linux'))
                    distro_version = data.get('VERSION_ID', '')
                    distro_id = data.get('ID', '')
            except Exception:
                pass

            # System info
            hostname = platform.node() or 'localhost'
            is_root = os.geteuid() == 0
            kernel = platform.release()

            # Disk size
            disk = shutil.disk_usage('/')
            total_bytes = disk.total

            # Display name
            display_parts = [hostname]
            ver_str = f"{distro} {distro_version}".strip()
            if ver_str:
                display_parts.append(ver_str)
            display_name = ' - '.join(display_parts)

            device = UnifiedDeviceInfo(
                device_id='local_linux_system',
                device_type=DeviceType.LINUX_LOCAL_SYSTEM,
                display_name=display_name,
                status=DeviceStatus.READY,
                size_bytes=total_bytes,
                connection_time=datetime.now(),
                metadata={
                    'target_root': '/',
                    'distro': distro,
                    'distro_version': distro_version,
                    'distro_id': distro_id,
                    'hostname': hostname,
                    'kernel': kernel,
                    'is_root': is_root,
                    'detected_os': 'linux',
                },
                is_selectable=True,
            )

            if not is_root:
                logger.warning(
                    "Linux local collection: running without root. "
                    "Some artifacts (shadow, audit logs, journald) will be inaccessible."
                )

            return [device]

        except Exception as e:
            logger.error(f"Linux local enumeration failed: {e}")
            return []


# =============================================================================
# Factory Function
# =============================================================================

def create_default_enumerators() -> Dict[str, BaseDeviceEnumerator]:
    """
    Create default enumerator set

    Returns:
        Name -> enumerator mapping
    """
    enumerators = {}

    # Windows disks (Windows only)
    if sys.platform == 'win32':
        windows = WindowsDiskEnumerator()
        if windows.is_available():
            enumerators['windows'] = windows

    # macOS local system (macOS only)
    if sys.platform == 'darwin':
        macos_local = macOSLocalEnumerator()
        if macos_local.is_available():
            enumerators['macos_local'] = macos_local

    # Linux local system (Linux only)
    if sys.platform.startswith('linux'):
        linux_local = LinuxLocalEnumerator()
        if linux_local.is_available():
            enumerators['linux_local'] = linux_local

    # Android
    android = AndroidDeviceEnumerator()
    if android.is_available():
        enumerators['android'] = android

    # iOS backup
    ios_backup = iOSBackupEnumerator()
    if ios_backup.is_available():
        enumerators['ios_backup'] = ios_backup

    # iOS USB device
    ios_device = iOSDeviceEnumerator()
    if ios_device.is_available():
        enumerators['ios_device'] = ios_device

    # Forensic images (always available)
    enumerators['images'] = ForensicImageEnumerator()

    # Hardware-level enumerators (EDL / MTK BROM via USB VID/PID)
    hw_enum = AndroidHardwareEnumerator()
    if hw_enum.is_available():
        enumerators['android_hardware'] = hw_enum

    # WiFi ADB enumerator
    wifi_enum = AndroidWiFiDeviceEnumerator()
    if wifi_enum.is_available():
        enumerators['android_wifi'] = wifi_enum

    logger.info(f"Created {len(enumerators)} device enumerators: {list(enumerators.keys())}")
    return enumerators


def diagnose_device_prerequisites() -> dict:
    """
    Check device connection prerequisites and return diagnostic results.

    Returns:
        {
            'ios': {'driver_installed': bool, 'library_available': bool},
            'android': {'adb_available': bool},
        }

    Security: This function only checks for the presence of software
    components. It does not access any device data, network resources,
    or execute external binaries.
    """
    result = {
        'ios': {'driver_installed': False, 'library_available': False},
        'android': {'adb_available': False},
    }

    # iOS: check pymobiledevice3 availability
    try:
        from collectors.ios_collector import PYMOBILEDEVICE3_AVAILABLE
        result['ios']['library_available'] = PYMOBILEDEVICE3_AVAILABLE
    except Exception:
        try:
            import pymobiledevice3
            result['ios']['library_available'] = True
        except Exception:
            pass

    # iOS: check Apple driver — try actual usbmux connection first (most reliable).
    # PyInstaller exe has restricted registry access, so registry check is unreliable.
    if result['ios']['library_available']:
        try:
            from pymobiledevice3.usbmux import list_devices
            list_devices()  # Returns [] if no device, throws if driver missing
            result['ios']['driver_installed'] = True
        except Exception:
            pass

    # Fallback: registry check (Windows) or usbmuxd binary check (Unix)
    if not result['ios']['driver_installed']:
        if sys.platform == 'win32':
            try:
                import winreg
                apple_keys = [
                    r"SOFTWARE\Apple Inc.\Apple Mobile Device Support",
                    r"SOFTWARE\Apple Computer, Inc.\Apple Mobile Device Support",
                    r"SOFTWARE\Apple Inc.\Apple Devices",
                    r"SOFTWARE\Wow6432Node\Apple Inc.\Apple Mobile Device Support",
                    r"SOFTWARE\Wow6432Node\Apple Inc.\Apple Devices",
                ]
                for key_path in apple_keys:
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path):
                            result['ios']['driver_installed'] = True
                            break
                    except OSError:
                        continue

                if not result['ios']['driver_installed']:
                    try:
                        svc_key = r"SYSTEM\CurrentControlSet\Services\Apple Mobile Device Service"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, svc_key):
                            result['ios']['driver_installed'] = True
                    except OSError:
                        pass
            except Exception:
                pass
        else:
            try:
                import shutil
                result['ios']['driver_installed'] = shutil.which('usbmuxd') is not None
            except Exception:
                pass

    # Android: check ADB availability
    try:
        from collectors.android_collector import ADB_AVAILABLE
        result['android']['adb_available'] = ADB_AVAILABLE
    except Exception:
        pass

    return result
