# -*- coding: utf-8 -*-
"""
Device List Panel (Simplified)

A compact UI for displaying device list.
"""

from typing import Dict, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QScrollArea,
    QCheckBox, QLabel, QFrame, QPushButton, QFileDialog
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from core.device_manager import (
    UnifiedDeviceManager,
    UnifiedDeviceInfo,
    DeviceType,
    DeviceStatus
)
from gui.styles import COLORS


class DeviceListPanel(QWidget):
    """
    Compact device list panel
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
        layout.setSpacing(4)

        # Header row: buttons
        header_layout = QHBoxLayout()
        header_layout.setSpacing(4)
        header_layout.setContentsMargins(0, 0, 0, 4)

        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setFixedHeight(20)
        refresh_btn.clicked.connect(self._on_refresh_clicked)
        header_layout.addWidget(refresh_btn)

        # Add image button
        add_btn = QPushButton("+ Add E01/RAW")
        add_btn.setFixedHeight(20)
        add_btn.clicked.connect(self._on_add_image_clicked)
        header_layout.addWidget(add_btn)

        header_layout.addStretch()

        # Selection summary
        self.summary_label = QLabel("0 selected")
        self.summary_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10px;")
        header_layout.addWidget(self.summary_label)

        layout.addLayout(header_layout)

        # Scroll area (device list)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; }")

        # Device list container
        self.devices_container = QWidget()
        self.devices_layout = QVBoxLayout(self.devices_container)
        self.devices_layout.setContentsMargins(0, 0, 0, 0)
        self.devices_layout.setSpacing(2)

        # Empty state label (displayed when no devices)
        self.empty_label = QLabel("No devices detected. Click 'Refresh' or '+ Add E01/RAW'")
        self.empty_label.setStyleSheet(f"color: {COLORS['text_tertiary']}; font-size: 9px;")
        self.empty_label.setWordWrap(True)
        self.devices_layout.addWidget(self.empty_label)

        self.devices_layout.addStretch()

        scroll.setWidget(self.devices_container)
        scroll.setMinimumHeight(40)
        layout.addWidget(scroll, 1)

    def _connect_signals(self):
        """Connect signals"""
        self.device_manager.device_added.connect(self._on_device_added)
        self.device_manager.device_removed.connect(self._on_device_removed)
        self.device_manager.device_updated.connect(self._on_device_updated)

    def _on_device_added(self, device: UnifiedDeviceInfo):
        """Device added"""
        if device.device_id in self.device_checkboxes:
            return

        # Hide empty state label
        self.empty_label.hide()

        # Create checkbox
        cb = QCheckBox(self._get_device_label(device))
        cb.setChecked(device.is_selected)
        cb.setEnabled(device.is_selectable)
        cb.setProperty("device_id", device.device_id)
        cb.stateChanged.connect(lambda state, d=device.device_id: self._on_checkbox_changed(d, state))

        # Tooltip
        cb.setToolTip(self._get_device_tooltip(device))

        self.device_checkboxes[device.device_id] = cb

        # Insert before stretch
        self.devices_layout.insertWidget(self.devices_layout.count() - 1, cb)
        self._update_summary()

    def _on_device_removed(self, device_id: str):
        """Device removed"""
        if device_id in self.device_checkboxes:
            cb = self.device_checkboxes.pop(device_id)
            self.devices_layout.removeWidget(cb)
            cb.deleteLater()
            self._update_summary()

            # Show empty state label if no devices
            if not self.device_checkboxes:
                self.empty_label.show()

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

    def _on_add_image_clicked(self):
        """Add image"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Forensic Image",
            "",
            "Forensic Images (*.E01 *.e01 *.Ex01 *.dd *.raw *.img *.bin);;All Files (*)"
        )

        if file_path:
            device = self.device_manager.add_image_file(file_path)
            if device:
                self.image_file_requested.emit()

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
            DeviceType.ANDROID_DEVICE: "📱",
            DeviceType.IOS_BACKUP: "🍎",
            DeviceType.IOS_DEVICE: "📲",  # [2026-01-30] iOS USB direct connection
        }
        icon = type_icons.get(device.device_type, "📁")
        label = device.display_name

        # [2026-02-15] Display volume letter(s) for Windows physical disks
        if device.device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
            all_volumes = device.metadata.get('all_volumes', [])
            if all_volumes:
                volumes_str = ', '.join(f"{v}:" for v in all_volumes)
                label = f"{label} [{volumes_str}]"

        # [New] Display detected OS for E01/RAW images
        if device.device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE):
            detected_os = device.metadata.get('detected_os', 'unknown')
            fs_type = device.metadata.get('filesystem_type', 'Unknown')

            if detected_os == 'windows':
                label = f"{label} [Win/{fs_type}]"
            elif detected_os == 'linux':
                label = f"{label} [Linux/{fs_type}]"
            elif detected_os == 'macos':
                label = f"{label} [macOS/{fs_type}]"
            elif detected_os != 'unknown':
                label = f"{label} [{detected_os}/{fs_type}]"

        return f"{icon} {label}"

    def _get_device_tooltip(self, device: UnifiedDeviceInfo) -> str:
        """Device tooltip"""
        lines = [
            f"Type: {device.device_type.name}",
            f"Size: {device.size_display}",
            f"Status: {device.status.name}",
        ]

        # [New] Add OS info and direct collection note for E01/RAW images
        if device.device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE):
            detected_os = device.metadata.get('detected_os', 'unknown')
            fs_type = device.metadata.get('filesystem_type', 'Unknown')
            lines.append(f"Filesystem: {fs_type}")
            lines.append(f"Detected OS: {detected_os.upper()}")
            lines.append("✅ Direct collection supported (no mount required)")

        if not device.is_selectable:
            lines.append(f"⚠ {device.selection_disabled_reason}")
        return "\n".join(lines)

    def get_selected_devices(self):
        """Get selected device list"""
        return self.device_manager.get_selected_devices()
