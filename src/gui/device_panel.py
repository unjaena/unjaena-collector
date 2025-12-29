# -*- coding: utf-8 -*-
"""
Device List Panel

디바이스 목록 UI 컴포넌트.
모든 유형의 디바이스를 카테고리별로 표시하고 선택 기능을 제공합니다.

Components:
    - DeviceCard: 개별 디바이스 카드
    - DeviceCategoryGroup: 카테고리별 그룹
    - DeviceListPanel: 전체 디바이스 목록 패널
"""

from typing import Dict, Optional, Callable
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QScrollArea,
    QCheckBox, QLabel, QFrame, QPushButton, QFileDialog,
    QGroupBox, QSizePolicy, QSpacerItem
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from core.device_manager import (
    UnifiedDeviceManager,
    UnifiedDeviceInfo,
    DeviceType,
    DeviceStatus
)
from gui.styles import COLORS, get_status_color, get_device_type_color


# =============================================================================
# Device Card
# =============================================================================

class DeviceCard(QFrame):
    """
    개별 디바이스 표시 카드

    체크박스, 디바이스 정보, 상태 표시를 포함합니다.

    Signals:
        selection_changed(device_id, selected): 선택 상태 변경 시
    """

    selection_changed = pyqtSignal(str, bool)

    def __init__(self, device: UnifiedDeviceInfo, parent=None):
        super().__init__(parent)
        self.device = device
        self._setup_ui()
        self._update_selection_style()

    def _setup_ui(self):
        """UI 구성"""
        self.setObjectName("deviceCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(12)

        # 체크박스
        self.checkbox = QCheckBox()
        self.checkbox.setChecked(self.device.is_selected)
        self.checkbox.setEnabled(self.device.is_selectable)
        self.checkbox.stateChanged.connect(self._on_checkbox_changed)
        layout.addWidget(self.checkbox)

        # 디바이스 정보
        info_layout = QVBoxLayout()
        info_layout.setSpacing(4)

        # 이름 행
        name_layout = QHBoxLayout()
        name_layout.setSpacing(8)

        # 디바이스 유형 아이콘/색상
        type_indicator = QLabel("●")
        type_indicator.setStyleSheet(f"color: {get_device_type_color(self.device.device_type.name)};")
        type_indicator.setFixedWidth(16)
        name_layout.addWidget(type_indicator)

        # 디바이스 이름
        self.name_label = QLabel(self.device.display_name)
        self.name_label.setFont(QFont("Pretendard", 11, QFont.Weight.Medium))
        name_layout.addWidget(self.name_label, 1)

        info_layout.addLayout(name_layout)

        # 상세 정보 행
        details = self._get_device_details()
        self.detail_label = QLabel(details)
        self.detail_label.setObjectName("mutedLabel")
        self.detail_label.setFont(QFont("Pretendard", 9))
        info_layout.addWidget(self.detail_label)

        layout.addLayout(info_layout, 1)

        # 상태 표시
        self.status_label = QLabel(self._get_status_text())
        self.status_label.setObjectName(self._get_status_object_name())
        self.status_label.setFont(QFont("Pretendard", 10, QFont.Weight.Medium))
        layout.addWidget(self.status_label)

    def _get_device_details(self) -> str:
        """디바이스 유형별 상세 정보 문자열"""
        d = self.device
        m = d.metadata

        if d.device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
            partitions = m.get('partitions', 0)
            return f"Drive {m.get('drive_number', '?')} | {partitions} partitions | {d.size_display}"

        elif d.device_type == DeviceType.E01_IMAGE:
            segments = m.get('segments', [])
            seg_count = len(segments) if segments else 1
            return f"E01 Image | {seg_count} segments | {d.size_display}"

        elif d.device_type == DeviceType.RAW_IMAGE:
            return f"RAW Image | {d.size_display}"

        elif d.device_type == DeviceType.ANDROID_DEVICE:
            android_ver = m.get('android_version', '?')
            rooted = "Rooted" if m.get('rooted') else "Not Rooted"
            return f"Android {android_ver} | {rooted}"

        elif d.device_type == DeviceType.IOS_BACKUP:
            ios_ver = m.get('ios_version', '?')
            backup_date = m.get('backup_date', '')[:10] if m.get('backup_date') else '?'
            return f"iOS {ios_ver} | Backup: {backup_date}"

        return d.size_display if d.size_display else ""

    def _get_status_text(self) -> str:
        """상태 텍스트"""
        status_map = {
            DeviceStatus.READY: "Ready",
            DeviceStatus.CONNECTED: "Connected",
            DeviceStatus.BUSY: "Busy",
            DeviceStatus.ERROR: "Error",
            DeviceStatus.LOCKED: "Locked",
            DeviceStatus.DISCONNECTED: "Disconnected",
        }
        return status_map.get(self.device.status, "Unknown")

    def _get_status_object_name(self) -> str:
        """상태에 따른 QLabel objectName"""
        status_map = {
            DeviceStatus.READY: "statusReady",
            DeviceStatus.CONNECTED: "statusReady",
            DeviceStatus.BUSY: "statusBusy",
            DeviceStatus.ERROR: "statusError",
            DeviceStatus.LOCKED: "statusLocked",
        }
        return status_map.get(self.device.status, "mutedLabel")

    def _on_checkbox_changed(self, state: int):
        """체크박스 상태 변경 핸들러"""
        selected = state == Qt.CheckState.Checked.value
        self.device.is_selected = selected
        self._update_selection_style()
        self.selection_changed.emit(self.device.device_id, selected)

    def _update_selection_style(self):
        """선택 상태에 따른 스타일 업데이트"""
        if self.device.is_selected:
            self.setObjectName("deviceCardSelected")
        else:
            self.setObjectName("deviceCard")
        self.setStyleSheet(self.styleSheet())  # 스타일 새로고침

    def mousePressEvent(self, event):
        """카드 클릭 시 체크박스 토글"""
        if self.device.is_selectable:
            self.checkbox.setChecked(not self.checkbox.isChecked())
        super().mousePressEvent(event)

    def update_device(self, device: UnifiedDeviceInfo):
        """디바이스 정보 업데이트"""
        self.device = device
        self.checkbox.setChecked(device.is_selected)
        self.name_label.setText(device.display_name)
        self.detail_label.setText(self._get_device_details())
        self.status_label.setText(self._get_status_text())
        self.status_label.setObjectName(self._get_status_object_name())
        self._update_selection_style()


# =============================================================================
# Device Category Group
# =============================================================================

class DeviceCategoryGroup(QWidget):
    """
    디바이스 카테고리 그룹

    동일 유형의 디바이스를 그룹화하여 표시합니다.
    """

    def __init__(self, title: str, device_type: DeviceType, parent=None):
        super().__init__(parent)
        self.title = title
        self.device_type = device_type
        self.device_cards: Dict[str, DeviceCard] = {}
        self._setup_ui()

    def _setup_ui(self):
        """UI 구성"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 16)
        layout.setSpacing(8)

        # 카테고리 헤더
        header_layout = QHBoxLayout()

        self.header_label = QLabel(self.title.upper())
        self.header_label.setObjectName("mutedLabel")
        self.header_label.setFont(QFont("Pretendard", 10, QFont.Weight.Bold))
        header_layout.addWidget(self.header_label)

        self.count_label = QLabel("(0)")
        self.count_label.setObjectName("mutedLabel")
        header_layout.addWidget(self.count_label)

        header_layout.addStretch()

        layout.addLayout(header_layout)

        # 디바이스 카드 컨테이너
        self.cards_layout = QVBoxLayout()
        self.cards_layout.setSpacing(6)
        layout.addLayout(self.cards_layout)

        # 빈 상태 메시지
        self.empty_label = QLabel("No devices detected")
        self.empty_label.setObjectName("mutedLabel")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setMinimumHeight(60)
        layout.addWidget(self.empty_label)

        self._update_visibility()

    def add_device(self, device: UnifiedDeviceInfo, on_selection_changed: Callable):
        """디바이스 카드 추가"""
        if device.device_id in self.device_cards:
            return

        card = DeviceCard(device)
        card.selection_changed.connect(on_selection_changed)
        self.device_cards[device.device_id] = card
        self.cards_layout.addWidget(card)
        self._update_count()
        self._update_visibility()

    def remove_device(self, device_id: str):
        """디바이스 카드 제거"""
        if device_id in self.device_cards:
            card = self.device_cards.pop(device_id)
            self.cards_layout.removeWidget(card)
            card.deleteLater()
            self._update_count()
            self._update_visibility()

    def update_device(self, device: UnifiedDeviceInfo):
        """디바이스 정보 업데이트"""
        if device.device_id in self.device_cards:
            self.device_cards[device.device_id].update_device(device)

    def _update_count(self):
        """카운트 라벨 업데이트"""
        self.count_label.setText(f"({len(self.device_cards)})")

    def _update_visibility(self):
        """비어있을 때 메시지 표시"""
        is_empty = len(self.device_cards) == 0
        self.empty_label.setVisible(is_empty)

    @property
    def device_count(self) -> int:
        return len(self.device_cards)


# =============================================================================
# Device List Panel
# =============================================================================

class DeviceListPanel(QWidget):
    """
    전체 디바이스 목록 패널

    모든 디바이스 카테고리를 포함하고 선택 관리를 수행합니다.

    Signals:
        selection_changed(): 선택 상태 변경 시
        image_file_requested(): 이미지 파일 추가 요청 시
    """

    selection_changed = pyqtSignal()
    image_file_requested = pyqtSignal()

    # 카테고리 정의
    CATEGORIES = [
        ("Physical Disks", DeviceType.WINDOWS_PHYSICAL_DISK),
        ("Forensic Images", DeviceType.E01_IMAGE),
        ("Android Devices", DeviceType.ANDROID_DEVICE),
        ("iOS Backups", DeviceType.IOS_BACKUP),
    ]

    def __init__(self, device_manager: UnifiedDeviceManager, parent=None):
        super().__init__(parent)
        self.device_manager = device_manager
        self.category_groups: Dict[DeviceType, DeviceCategoryGroup] = {}
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """UI 구성"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 헤더
        header = self._create_header()
        layout.addWidget(header)

        # 전체 선택 체크박스
        self.select_all_checkbox = QCheckBox("Select All")
        self.select_all_checkbox.stateChanged.connect(self._on_select_all_changed)
        select_all_container = QWidget()
        select_all_layout = QHBoxLayout(select_all_container)
        select_all_layout.setContentsMargins(16, 12, 16, 12)
        select_all_layout.addWidget(self.select_all_checkbox)
        layout.addWidget(select_all_container)

        # 구분선
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setStyleSheet(f"background-color: {COLORS['border_subtle']};")
        separator.setFixedHeight(1)
        layout.addWidget(separator)

        # 스크롤 영역
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        # 디바이스 목록 컨테이너
        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(16, 16, 16, 16)
        container_layout.setSpacing(0)

        # 카테고리 그룹 생성
        for title, device_type in self.CATEGORIES:
            group = DeviceCategoryGroup(title, device_type)
            self.category_groups[device_type] = group
            container_layout.addWidget(group)

        # RAW 이미지는 E01 그룹에 포함
        self.category_groups[DeviceType.RAW_IMAGE] = self.category_groups[DeviceType.E01_IMAGE]

        container_layout.addStretch()
        scroll.setWidget(container)
        layout.addWidget(scroll, 1)

        # 푸터 (선택 요약)
        footer = self._create_footer()
        layout.addWidget(footer)

    def _create_header(self) -> QWidget:
        """헤더 위젯 생성"""
        header = QWidget()
        header.setStyleSheet(f"background-color: {COLORS['bg_secondary']};")

        layout = QHBoxLayout(header)
        layout.setContentsMargins(16, 12, 16, 12)

        # 제목
        title = QLabel("Connected Devices")
        title.setObjectName("headerLabel")
        layout.addWidget(title)

        layout.addStretch()

        # 새로고침 버튼
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setObjectName("iconButton")
        refresh_btn.clicked.connect(self._on_refresh_clicked)
        layout.addWidget(refresh_btn)

        # 이미지 추가 버튼
        add_image_btn = QPushButton("+ Add Image")
        add_image_btn.clicked.connect(self._on_add_image_clicked)
        layout.addWidget(add_image_btn)

        return header

    def _create_footer(self) -> QWidget:
        """푸터 위젯 생성"""
        footer = QWidget()
        footer.setStyleSheet(f"""
            background-color: {COLORS['bg_secondary']};
            border-top: 1px solid {COLORS['border_subtle']};
        """)

        layout = QHBoxLayout(footer)
        layout.setContentsMargins(16, 12, 16, 12)

        self.selection_summary = QLabel("Selected: 0 devices")
        self.selection_summary.setObjectName("subheaderLabel")
        layout.addWidget(self.selection_summary)

        layout.addStretch()

        # 선택 해제 버튼
        clear_btn = QPushButton("Clear Selection")
        clear_btn.setObjectName("iconButton")
        clear_btn.clicked.connect(self._on_clear_selection)
        layout.addWidget(clear_btn)

        return footer

    def _connect_signals(self):
        """시그널 연결"""
        self.device_manager.device_added.connect(self._on_device_added)
        self.device_manager.device_removed.connect(self._on_device_removed)
        self.device_manager.device_updated.connect(self._on_device_updated)
        self.device_manager.selection_changed.connect(self._update_selection_summary)

    def _on_device_added(self, device: UnifiedDeviceInfo):
        """디바이스 추가 핸들러"""
        device_type = device.device_type

        # RAW 이미지는 E01 그룹에 표시
        if device_type == DeviceType.RAW_IMAGE:
            device_type = DeviceType.E01_IMAGE

        if device_type in self.category_groups:
            self.category_groups[device_type].add_device(
                device,
                self._on_device_selection_changed
            )

    def _on_device_removed(self, device_id: str):
        """디바이스 제거 핸들러"""
        for group in self.category_groups.values():
            group.remove_device(device_id)

    def _on_device_updated(self, device: UnifiedDeviceInfo):
        """디바이스 업데이트 핸들러"""
        device_type = device.device_type
        if device_type == DeviceType.RAW_IMAGE:
            device_type = DeviceType.E01_IMAGE

        if device_type in self.category_groups:
            self.category_groups[device_type].update_device(device)

    def _on_device_selection_changed(self, device_id: str, selected: bool):
        """개별 디바이스 선택 변경 핸들러"""
        self.device_manager.select_device(device_id, selected)
        self._update_select_all_state()
        self.selection_changed.emit()

    def _on_select_all_changed(self, state: int):
        """전체 선택 변경 핸들러"""
        if state == Qt.CheckState.Checked.value:
            self.device_manager.select_all()
        elif state == Qt.CheckState.Unchecked.value:
            self.device_manager.deselect_all()
        self.selection_changed.emit()

    def _update_select_all_state(self):
        """전체 선택 체크박스 상태 업데이트"""
        total = self.device_manager.total_count
        selected = self.device_manager.selected_count

        self.select_all_checkbox.blockSignals(True)
        if selected == 0:
            self.select_all_checkbox.setCheckState(Qt.CheckState.Unchecked)
        elif selected == total:
            self.select_all_checkbox.setCheckState(Qt.CheckState.Checked)
        else:
            self.select_all_checkbox.setCheckState(Qt.CheckState.PartiallyChecked)
        self.select_all_checkbox.blockSignals(False)

    def _update_selection_summary(self):
        """선택 요약 업데이트"""
        count = self.device_manager.selected_count
        self.selection_summary.setText(f"Selected: {count} device{'s' if count != 1 else ''}")
        self._update_select_all_state()

    def _on_refresh_clicked(self):
        """새로고침 버튼 클릭"""
        self.device_manager.refresh()

    def _on_add_image_clicked(self):
        """이미지 추가 버튼 클릭"""
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

    def _on_clear_selection(self):
        """선택 해제 버튼 클릭"""
        self.device_manager.deselect_all()
        self.selection_changed.emit()

    def get_selected_devices(self):
        """선택된 디바이스 목록 반환"""
        return self.device_manager.get_selected_devices()
