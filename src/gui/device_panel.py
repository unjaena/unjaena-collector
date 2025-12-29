# -*- coding: utf-8 -*-
"""
Device List Panel (Simplified)

디바이스 목록을 간단하게 표시하는 컴팩트 UI.
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
    컴팩트한 디바이스 목록 패널
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
        """UI 구성"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # 헤더 행: 버튼들
        header_layout = QHBoxLayout()
        header_layout.setSpacing(8)

        # 새로고침 버튼
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setFixedHeight(24)
        refresh_btn.clicked.connect(self._on_refresh_clicked)
        header_layout.addWidget(refresh_btn)

        # 이미지 추가 버튼
        add_btn = QPushButton("+ Add E01/RAW")
        add_btn.setFixedHeight(24)
        add_btn.clicked.connect(self._on_add_image_clicked)
        header_layout.addWidget(add_btn)

        header_layout.addStretch()

        # 선택 요약
        self.summary_label = QLabel("0 selected")
        self.summary_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        header_layout.addWidget(self.summary_label)

        layout.addLayout(header_layout)

        # 스크롤 영역 (디바이스 목록)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; }")

        # 디바이스 목록 컨테이너
        self.devices_container = QWidget()
        self.devices_layout = QVBoxLayout(self.devices_container)
        self.devices_layout.setContentsMargins(0, 0, 0, 0)
        self.devices_layout.setSpacing(2)
        self.devices_layout.addStretch()

        scroll.setWidget(self.devices_container)
        layout.addWidget(scroll, 1)

    def _connect_signals(self):
        """시그널 연결"""
        self.device_manager.device_added.connect(self._on_device_added)
        self.device_manager.device_removed.connect(self._on_device_removed)
        self.device_manager.device_updated.connect(self._on_device_updated)

    def _on_device_added(self, device: UnifiedDeviceInfo):
        """디바이스 추가"""
        if device.device_id in self.device_checkboxes:
            return

        # 체크박스 생성
        cb = QCheckBox(self._get_device_label(device))
        cb.setChecked(device.is_selected)
        cb.setEnabled(device.is_selectable)
        cb.setProperty("device_id", device.device_id)
        cb.stateChanged.connect(lambda state, d=device.device_id: self._on_checkbox_changed(d, state))

        # 툴팁
        cb.setToolTip(self._get_device_tooltip(device))

        self.device_checkboxes[device.device_id] = cb

        # stretch 전에 삽입
        self.devices_layout.insertWidget(self.devices_layout.count() - 1, cb)
        self._update_summary()

    def _on_device_removed(self, device_id: str):
        """디바이스 제거"""
        if device_id in self.device_checkboxes:
            cb = self.device_checkboxes.pop(device_id)
            self.devices_layout.removeWidget(cb)
            cb.deleteLater()
            self._update_summary()

    def _on_device_updated(self, device: UnifiedDeviceInfo):
        """디바이스 업데이트"""
        if device.device_id in self.device_checkboxes:
            cb = self.device_checkboxes[device.device_id]
            cb.setText(self._get_device_label(device))
            cb.setToolTip(self._get_device_tooltip(device))

    def _on_checkbox_changed(self, device_id: str, state: int):
        """체크박스 변경"""
        selected = state == Qt.CheckState.Checked.value
        self.device_manager.select_device(device_id, selected)
        self._update_summary()
        self.selection_changed.emit()

    def _on_refresh_clicked(self):
        """새로고침"""
        self.device_manager.refresh()

    def _on_add_image_clicked(self):
        """이미지 추가"""
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
        """선택 요약 업데이트"""
        count = sum(1 for cb in self.device_checkboxes.values() if cb.isChecked())
        total = len(self.device_checkboxes)
        self.summary_label.setText(f"{count}/{total} selected")

    def _get_device_label(self, device: UnifiedDeviceInfo) -> str:
        """디바이스 표시 라벨"""
        type_icons = {
            DeviceType.WINDOWS_PHYSICAL_DISK: "💿",
            DeviceType.E01_IMAGE: "📀",
            DeviceType.RAW_IMAGE: "📀",
            DeviceType.ANDROID_DEVICE: "📱",
            DeviceType.IOS_BACKUP: "🍎",
        }
        icon = type_icons.get(device.device_type, "📁")
        return f"{icon} {device.display_name}"

    def _get_device_tooltip(self, device: UnifiedDeviceInfo) -> str:
        """디바이스 툴팁"""
        lines = [
            f"Type: {device.device_type.name}",
            f"Size: {device.size_display}",
            f"Status: {device.status.name}",
        ]
        if not device.is_selectable:
            lines.append(f"⚠ {device.selection_disabled_reason}")
        return "\n".join(lines)

    def get_selected_devices(self):
        """선택된 디바이스 목록"""
        return self.device_manager.get_selected_devices()
