# -*- coding: utf-8 -*-
"""
Device List Panel

Displays detected devices and mobile connection status with
beginner-friendly setup guidance.
"""

import sys
from typing import Dict
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QCheckBox, QLabel, QPushButton, QFileDialog
)
from PyQt6.QtCore import Qt, pyqtSignal

from core.device_manager import (
    UnifiedDeviceManager,
    UnifiedDeviceInfo,
    DeviceType,
    DeviceStatus
)
from core.device_enumerators import diagnose_device_prerequisites
from gui.styles import COLORS


class DeviceListPanel(QWidget):
    """
    Device list panel with mobile connection guide.
    """

    selection_changed = pyqtSignal()
    image_file_requested = pyqtSignal()

    def __init__(self, device_manager: UnifiedDeviceManager, parent=None):
        super().__init__(parent)
        self.device_manager = device_manager
        self.device_checkboxes: Dict[str, QCheckBox] = {}
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Setup UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Header row
        header = QHBoxLayout()
        header.setSpacing(4)
        header.setContentsMargins(0, 0, 0, 0)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setFixedHeight(20)
        refresh_btn.clicked.connect(self._on_refresh_clicked)
        header.addWidget(refresh_btn)

        add_btn = QPushButton("+ Add Disk Image")
        add_btn.setFixedHeight(20)
        add_btn.clicked.connect(self._on_add_image_clicked)
        header.addWidget(add_btn)

        header.addStretch()

        self.summary_label = QLabel("0 selected")
        self.summary_label.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px;"
        )
        header.addWidget(self.summary_label)

        layout.addLayout(header)

        # Device list (no scroll — typically 1-5 items)
        self.devices_container = QWidget()
        self.devices_layout = QVBoxLayout(self.devices_container)
        self.devices_layout.setContentsMargins(0, 0, 0, 0)
        self.devices_layout.setSpacing(2)
        layout.addWidget(self.devices_container)

        # Mobile connection guide (always visible)
        self.mobile_guide = QLabel()
        self.mobile_guide.setWordWrap(True)
        self.mobile_guide.setTextFormat(Qt.TextFormat.RichText)
        self.mobile_guide.setOpenExternalLinks(False)
        self.mobile_guide.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 9px; "
            f"background: {COLORS['bg_tertiary']}; "
            f"border: 1px solid {COLORS['border_subtle']}; "
            f"border-radius: 4px; padding: 6px;"
        )
        self._update_mobile_guide()
        layout.addWidget(self.mobile_guide)

    def _connect_signals(self):
        """Connect signals"""
        self.device_manager.device_added.connect(self._on_device_added)
        self.device_manager.device_removed.connect(self._on_device_removed)
        self.device_manager.device_updated.connect(self._on_device_updated)

    # =========================================================================
    # Mobile Connection Guide
    # =========================================================================

    def _update_mobile_guide(self):
        """Build beginner-friendly mobile connection guide."""
        try:
            diag = diagnose_device_prerequisites()
        except Exception:
            diag = {
                'ios': {'driver_installed': False, 'library_available': False},
                'android': {'adb_available': False},
            }

        has_ios = any(
            did.startswith('ios_') for did in self.device_checkboxes
        )
        has_android = any(
            did.startswith('android_') for did in self.device_checkboxes
        )

        ok = COLORS['success']       # #3fb950
        warn = COLORS['warning']     # #d29922
        err = COLORS['error']        # #f85149
        dim = COLORS['text_tertiary']

        sections = []

        # --- iOS ---
        ios = diag['ios']
        if has_ios:
            sections.append(
                f"<span style='color:{ok};'>● iOS — Connected</span>"
            )
        elif not ios['driver_installed']:
            steps = self._ios_install_steps()
            sections.append(
                f"<span style='color:{err};'>● iOS — Setup Required</span>"
                f"<br><span style='color:{dim};'>{steps}</span>"
            )
        elif not ios['library_available']:
            sections.append(
                f"<span style='color:{err};'>● iOS — Library Unavailable</span>"
                f"<br><span style='color:{dim};'>"
                "Reinstall the collector or run: pip install pymobiledevice3"
                "</span>"
            )
        else:
            sections.append(
                f"<span style='color:{warn};'>● iOS — Ready</span>"
                f"<br><span style='color:{dim};'>"
                "1. Connect iPhone/iPad via USB cable<br>"
                "2. Unlock the device<br>"
                '3. Tap <b>"Trust"</b> when prompted on the device screen'
                "</span>"
            )

        # --- Android ---
        adb = diag['android']
        if has_android:
            sections.append(
                f"<span style='color:{ok};'>● Android — Connected</span>"
            )
        elif not adb['adb_available']:
            sections.append(
                f"<span style='color:{err};'>● Android — Setup Required</span>"
                f"<br><span style='color:{dim};'>"
                "On the Android device:<br>"
                "1. <b>Settings</b> > <b>About Phone</b> > "
                "tap <b>Build Number</b> 7 times<br>"
                "2. <b>Settings</b> > <b>Developer Options</b> > "
                "enable <b>USB Debugging</b><br>"
                "3. Connect via USB and tap <b>Allow</b> on the device"
                "</span>"
            )
        else:
            sections.append(
                f"<span style='color:{warn};'>● Android — Ready</span>"
                f"<br><span style='color:{dim};'>"
                "1. Connect the device via USB cable<br>"
                '2. Tap <b>"Allow USB Debugging"</b> on the device screen'
                "</span>"
            )

        # --- E01/RAW hint ---
        sections.append(
            f"<span style='color:{dim};'>"
            "● <b>E01/RAW</b>: Use <b>+ Add E01/RAW</b> button above"
            "</span>"
        )

        self.mobile_guide.setText(
            "<br>".join(sections)
        )

    @staticmethod
    def _ios_install_steps() -> str:
        """Return iOS driver install steps based on OS."""
        if sys.platform == 'win32':
            return (
                "iTunes is required for iOS connection:<br>"
                "1. Open <b>Microsoft Store</b> and search "
                "<b>\"Apple Devices\"</b><br>"
                "2. Install and restart this collector<br>"
                "3. Connect iPhone/iPad via USB cable<br>"
                '4. Tap <b>"Trust"</b> on the device screen'
            )
        elif sys.platform == 'darwin':
            return (
                "On macOS 10.15+, iOS support is built-in.<br>"
                "1. Connect iPhone/iPad via USB cable<br>"
                '2. Tap <b>"Trust"</b> on the device screen<br>'
                "If not detected: install Xcode Command Line Tools"
            )
        else:
            return (
                "Install required packages:<br>"
                "1. <b>sudo apt install libimobiledevice-utils "
                "usbmuxd</b><br>"
                "2. <b>sudo systemctl start usbmuxd</b><br>"
                "3. Connect iPhone/iPad via USB cable<br>"
                '4. Tap <b>"Trust"</b> on the device screen'
            )

    # =========================================================================
    # Device Events
    # =========================================================================

    def _on_device_added(self, device: UnifiedDeviceInfo):
        """Device added"""
        if device.device_id in self.device_checkboxes:
            return

        cb = QCheckBox(self._get_device_label(device))
        cb.setChecked(device.is_selected)
        cb.setEnabled(device.is_selectable)
        cb.setProperty("device_id", device.device_id)
        cb.stateChanged.connect(
            lambda state, d=device.device_id: self._on_checkbox_changed(d, state)
        )
        cb.setToolTip(self._get_device_tooltip(device))

        self.device_checkboxes[device.device_id] = cb
        self.devices_layout.addWidget(cb)
        self._update_summary()
        self._update_mobile_guide()

    def _on_device_removed(self, device_id: str):
        """Device removed"""
        if device_id in self.device_checkboxes:
            cb = self.device_checkboxes.pop(device_id)
            self.devices_layout.removeWidget(cb)
            cb.deleteLater()
            self._update_summary()
            self._update_mobile_guide()

    def _on_device_updated(self, device: UnifiedDeviceInfo):
        """Device updated"""
        if device.device_id in self.device_checkboxes:
            cb = self.device_checkboxes[device.device_id]
            cb.setText(self._get_device_label(device))
            cb.setToolTip(self._get_device_tooltip(device))

    def _on_checkbox_changed(self, device_id: str, state: int):
        """Checkbox changed"""
        selected = state == Qt.CheckState.Checked.value
        self.device_manager.select_device(device_id, selected)
        self._update_summary()
        self.selection_changed.emit()

    def _on_refresh_clicked(self):
        """Refresh"""
        self.device_manager.refresh()
        self._update_mobile_guide()

    def _on_add_image_clicked(self):
        """Add image"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Forensic Image",
            "",
            "Forensic Images (*.E01 *.e01 *.Ex01 *.dd *.raw *.img *.bin *.vmdk *.vhd *.vhdx *.qcow2 *.vdi)"
            ";;All Files (*)"
        )
        if file_path:
            device = self.device_manager.add_image_file(file_path)
            if device:
                self.image_file_requested.emit()

    # =========================================================================
    # Display Helpers
    # =========================================================================

    def _update_summary(self):
        """Update selection summary"""
        count = sum(1 for cb in self.device_checkboxes.values() if cb.isChecked())
        total = len(self.device_checkboxes)
        self.summary_label.setText(f"{count}/{total} selected")

    def _get_device_label(self, device: UnifiedDeviceInfo) -> str:
        """Device display label"""
        type_icons = {
            DeviceType.WINDOWS_PHYSICAL_DISK: "💿",
            DeviceType.E01_IMAGE: "📀",
            DeviceType.RAW_IMAGE: "📀",
            DeviceType.VMDK_IMAGE: "📀",
            DeviceType.VHD_IMAGE: "📀",
            DeviceType.VHDX_IMAGE: "📀",
            DeviceType.QCOW2_IMAGE: "📀",
            DeviceType.VDI_IMAGE: "📀",
            DeviceType.ANDROID_DEVICE: "📱",
            DeviceType.IOS_BACKUP: "🍎",
            DeviceType.IOS_DEVICE: "📲",
        }
        icon = type_icons.get(device.device_type, "📁")
        label = device.display_name

        if device.device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
            all_volumes = device.metadata.get('all_volumes', [])
            if all_volumes:
                volumes_str = ', '.join(f"{v}:" for v in all_volumes)
                label = f"{label} [{volumes_str}]"

        if device.device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE,
                                        DeviceType.VMDK_IMAGE, DeviceType.VHD_IMAGE,
                                        DeviceType.VHDX_IMAGE, DeviceType.QCOW2_IMAGE,
                                        DeviceType.VDI_IMAGE):
            detected_os = device.metadata.get('detected_os', 'unknown')
            fs_type = device.metadata.get('filesystem_type', 'Unknown')
            os_labels = {
                'windows': 'Win', 'linux': 'Linux', 'macos': 'macOS'
            }
            os_tag = os_labels.get(detected_os)
            if os_tag:
                label = f"{label} [{os_tag}/{fs_type}]"
            elif detected_os != 'unknown':
                label = f"{label} [{detected_os}/{fs_type}]"

        if device.device_type == DeviceType.ANDROID_DEVICE:
            android_ver = device.metadata.get('android_version', '')
            sdk = device.metadata.get('sdk_version', 0)
            rooted = device.metadata.get('rooted', False)
            root_tag = " [ROOT]" if rooted else ""
            ver_tag = f" [Android {android_ver}/SDK {sdk}]" if android_ver else ""
            label = f"{label}{ver_tag}{root_tag}"

        return f"{icon} {label}"

    def _get_device_tooltip(self, device: UnifiedDeviceInfo) -> str:
        """Device tooltip"""
        lines = [
            f"Type: {device.device_type.name}",
            f"Size: {device.size_display}",
            f"Status: {device.status.name}",
        ]

        if device.device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE,
                                        DeviceType.VMDK_IMAGE, DeviceType.VHD_IMAGE,
                                        DeviceType.VHDX_IMAGE, DeviceType.QCOW2_IMAGE,
                                        DeviceType.VDI_IMAGE):
            detected_os = device.metadata.get('detected_os', 'unknown')
            fs_type = device.metadata.get('filesystem_type', 'Unknown')
            lines.append(f"Filesystem: {fs_type}")
            lines.append(f"Detected OS: {detected_os.upper()}")

        if device.device_type == DeviceType.ANDROID_DEVICE:
            m = device.metadata
            android_ver = m.get('android_version', '?')
            sdk = m.get('sdk_version', 0)
            patch = m.get('security_patch', '') or 'Unknown'
            rooted = m.get('rooted', False)
            usb_dbg = m.get('usb_debugging', False)
            serial = m.get('serial', '')

            lines.append(f"Android {android_ver} (SDK {sdk})")
            lines.append(f"Security Patch: {patch}")
            lines.append(f"Root: {'Yes' if rooted else 'No'}")
            lines.append(f"USB Debugging: {'Enabled' if usb_dbg else 'Disabled'}")
            if serial:
                lines.append(f"Serial: ...{serial[-8:]}")
            lines.append("─────────────────────")

            phase_cve = (31 <= sdk <= 33) and (not patch or patch < '2024-10-01')
            available = ["sdcard (Phase 1)", "ADB Backup (Phase 3e)"]
            if phase_cve:
                available.append("CVE-2024-0044 (Phase 3a)")
            if rooted:
                available.append("Root full access")
            unavailable = []
            if not rooted:
                unavailable.append("App internal DB (root required)")
            if not phase_cve:
                unavailable.append("CVE-2024-0044 (SDK 31–33 only)")

            lines.append("Available: " + ", ".join(available))
            if unavailable:
                lines.append("Unavailable: " + ", ".join(unavailable))

        if not device.is_selectable:
            lines.append(f"⚠ {device.selection_disabled_reason}")
        return "\n".join(lines)

    def get_selected_devices(self):
        """Get selected device list"""
        return self.device_manager.get_selected_devices()
