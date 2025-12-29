# -*- coding: utf-8 -*-
"""
Multi-Progress Panel

복수 디바이스 수집 진행률 표시 패널.

Features:
    - 디바이스별 진행률 바
    - 현재 수집 중인 아티팩트 표시
    - 완료/실패 상태 아이콘
    - 전체 진행률
    - 취소 버튼
"""

from typing import Dict, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QFrame, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from core.multi_device_collector import MultiDeviceCollector, TaskStatus, CollectionResult
from core.device_manager import UnifiedDeviceInfo
from gui.styles import COLORS


# =============================================================================
# Device Progress Card
# =============================================================================

class DeviceProgressCard(QFrame):
    """
    개별 디바이스 진행률 카드

    디바이스명, 진행률, 현재 작업, 상태를 표시합니다.
    """

    def __init__(self, device: UnifiedDeviceInfo, parent=None):
        super().__init__(parent)
        self.device = device
        self.device_id = device.device_id
        self._setup_ui()
        self._apply_styles()

    def _setup_ui(self):
        """UI 구성"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        # 헤더 행: 이름 + 상태
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        # 디바이스 이름
        self.name_label = QLabel(self.device.display_name)
        self.name_label.setFont(QFont("Pretendard", 11, QFont.Weight.Medium))
        header_layout.addWidget(self.name_label, 1)

        # 상태 아이콘/텍스트
        self.status_label = QLabel("Pending")
        self.status_label.setObjectName("statusPending")
        header_layout.addWidget(self.status_label)

        layout.addLayout(header_layout)

        # 진행률 바
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(8)
        layout.addWidget(self.progress_bar)

        # 상세 정보 행: 현재 작업 + 수집 개수
        detail_layout = QHBoxLayout()
        detail_layout.setSpacing(12)

        self.current_task_label = QLabel("Waiting...")
        self.current_task_label.setObjectName("mutedLabel")
        self.current_task_label.setFont(QFont("Pretendard", 9))
        detail_layout.addWidget(self.current_task_label, 1)

        self.count_label = QLabel("")
        self.count_label.setObjectName("mutedLabel")
        self.count_label.setFont(QFont("Pretendard", 9))
        detail_layout.addWidget(self.count_label)

        layout.addLayout(detail_layout)

    def _apply_styles(self):
        """스타일 적용"""
        self.setStyleSheet(f"""
            DeviceProgressCard {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 8px;
            }}
            QLabel {{
                color: {COLORS['text_primary']};
            }}
            QLabel#mutedLabel {{
                color: {COLORS['text_tertiary']};
            }}
            QLabel#statusPending {{
                color: {COLORS['text_secondary']};
            }}
            QLabel#statusRunning {{
                color: {COLORS['warning']};
            }}
            QLabel#statusCompleted {{
                color: {COLORS['success']};
            }}
            QLabel#statusFailed {{
                color: {COLORS['error']};
            }}
            QProgressBar {{
                background-color: {COLORS['bg_tertiary']};
                border: none;
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background-color: {COLORS['brand_primary']};
                border-radius: 4px;
            }}
        """)

    def set_status(self, status: TaskStatus):
        """상태 업데이트"""
        status_map = {
            TaskStatus.PENDING: ("Pending", "statusPending"),
            TaskStatus.RUNNING: ("Running", "statusRunning"),
            TaskStatus.COMPLETED: ("Completed", "statusCompleted"),
            TaskStatus.FAILED: ("Failed", "statusFailed"),
            TaskStatus.CANCELLED: ("Cancelled", "statusFailed"),
        }

        text, obj_name = status_map.get(status, ("Unknown", "mutedLabel"))
        self.status_label.setText(text)
        self.status_label.setObjectName(obj_name)
        self.status_label.setStyleSheet(self.status_label.styleSheet())  # 스타일 새로고침

        # 완료 시 진행률 100%
        if status == TaskStatus.COMPLETED:
            self.progress_bar.setValue(100)
            self.current_task_label.setText("Done")

    def set_progress(self, progress: float, current_artifact: str = ""):
        """진행률 업데이트"""
        self.progress_bar.setValue(int(progress * 100))

        if current_artifact:
            self.current_task_label.setText(f"Collecting: {current_artifact}")

    def set_collected_count(self, count: int):
        """수집 개수 업데이트"""
        self.count_label.setText(f"{count} files")

    def set_error(self, error: str):
        """에러 표시"""
        self.current_task_label.setText(f"Error: {error}")
        self.current_task_label.setStyleSheet(f"color: {COLORS['error']};")


# =============================================================================
# Multi-Progress Panel
# =============================================================================

class MultiProgressPanel(QWidget):
    """
    복수 디바이스 진행률 패널

    모든 디바이스의 수집 진행 상황을 한눈에 보여줍니다.

    Signals:
        cancel_requested: 취소 버튼 클릭 시
    """

    cancel_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.device_cards: Dict[str, DeviceProgressCard] = {}
        self._collector: Optional[MultiDeviceCollector] = None
        self._setup_ui()
        self._apply_styles()

    def _setup_ui(self):
        """UI 구성"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 헤더
        header = self._create_header()
        layout.addWidget(header)

        # 스크롤 영역
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        # 디바이스 카드 컨테이너
        self.cards_container = QWidget()
        self.cards_layout = QVBoxLayout(self.cards_container)
        self.cards_layout.setContentsMargins(16, 16, 16, 16)
        self.cards_layout.setSpacing(12)
        self.cards_layout.addStretch()

        scroll.setWidget(self.cards_container)
        layout.addWidget(scroll, 1)

        # 푸터
        footer = self._create_footer()
        layout.addWidget(footer)

    def _create_header(self) -> QWidget:
        """헤더 생성"""
        header = QWidget()

        layout = QHBoxLayout(header)
        layout.setContentsMargins(16, 12, 16, 12)

        # 제목
        self.title_label = QLabel("Collection Progress")
        self.title_label.setObjectName("headerLabel")
        layout.addWidget(self.title_label)

        layout.addStretch()

        # 디바이스 카운트
        self.device_count_label = QLabel("0/0 devices")
        self.device_count_label.setObjectName("mutedLabel")
        layout.addWidget(self.device_count_label)

        return header

    def _create_footer(self) -> QWidget:
        """푸터 생성"""
        footer = QWidget()

        layout = QVBoxLayout(footer)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        # 전체 진행률
        progress_layout = QHBoxLayout()

        progress_label = QLabel("Overall Progress:")
        progress_layout.addWidget(progress_label)

        self.overall_progress = QProgressBar()
        self.overall_progress.setRange(0, 100)
        self.overall_progress.setValue(0)
        self.overall_progress.setObjectName("largeProgress")
        self.overall_progress.setFixedHeight(12)
        progress_layout.addWidget(self.overall_progress, 1)

        self.overall_percent_label = QLabel("0%")
        self.overall_percent_label.setFixedWidth(50)
        progress_layout.addWidget(self.overall_percent_label)

        layout.addLayout(progress_layout)

        # 버튼 영역
        button_layout = QHBoxLayout()

        # 수집 파일 수
        self.total_files_label = QLabel("0 files collected")
        self.total_files_label.setObjectName("mutedLabel")
        button_layout.addWidget(self.total_files_label)

        button_layout.addStretch()

        # 취소 버튼
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("dangerButton")
        self.cancel_btn.clicked.connect(self._on_cancel_clicked)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)

        return footer

    def _apply_styles(self):
        """스타일 적용"""
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {COLORS['bg_primary']};
                color: {COLORS['text_primary']};
            }}
            QLabel#headerLabel {{
                font-size: 16px;
                font-weight: 600;
            }}
            QLabel#mutedLabel {{
                color: {COLORS['text_tertiary']};
            }}
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 6px;
                padding: 8px 16px;
                color: {COLORS['text_primary']};
            }}
            QPushButton:hover {{
                background-color: {COLORS['bg_hover']};
            }}
            QPushButton#dangerButton {{
                background-color: {COLORS['error']};
                border: none;
                color: white;
            }}
            QPushButton#dangerButton:hover {{
                background-color: #ff6b63;
            }}
            QProgressBar {{
                background-color: {COLORS['bg_tertiary']};
                border: none;
                border-radius: 6px;
            }}
            QProgressBar::chunk {{
                background-color: {COLORS['brand_primary']};
                border-radius: 6px;
            }}
        """)

    def bind_collector(self, collector: MultiDeviceCollector):
        """수집기 바인딩"""
        self._collector = collector

        # 시그널 연결
        collector.collection_started.connect(self._on_collection_started)
        collector.collection_completed.connect(self._on_collection_completed)
        collector.device_started.connect(self._on_device_started)
        collector.device_progress.connect(self._on_device_progress)
        collector.device_completed.connect(self._on_device_completed)
        collector.artifact_collected.connect(self._on_artifact_collected)
        collector.error_occurred.connect(self._on_error_occurred)

    def add_device(self, device: UnifiedDeviceInfo):
        """디바이스 카드 추가"""
        if device.device_id in self.device_cards:
            return

        card = DeviceProgressCard(device)
        self.device_cards[device.device_id] = card

        # stretch 전에 삽입
        self.cards_layout.insertWidget(
            self.cards_layout.count() - 1,  # stretch 전
            card
        )

        self._update_device_count()

    def clear(self):
        """모든 카드 제거"""
        for card in self.device_cards.values():
            self.cards_layout.removeWidget(card)
            card.deleteLater()

        self.device_cards.clear()
        self.overall_progress.setValue(0)
        self.overall_percent_label.setText("0%")
        self.total_files_label.setText("0 files collected")
        self._update_device_count()

    def _update_device_count(self):
        """디바이스 카운트 업데이트"""
        completed = sum(
            1 for card in self.device_cards.values()
            if card.status_label.text() in ("Completed", "Failed")
        )
        total = len(self.device_cards)
        self.device_count_label.setText(f"{completed}/{total} devices")

    def _update_overall_progress(self):
        """전체 진행률 업데이트"""
        if not self.device_cards:
            return

        total_progress = sum(
            card.progress_bar.value()
            for card in self.device_cards.values()
        )
        avg_progress = total_progress // len(self.device_cards)

        self.overall_progress.setValue(avg_progress)
        self.overall_percent_label.setText(f"{avg_progress}%")

    # =========================================================================
    # Signal Handlers
    # =========================================================================

    def _on_collection_started(self):
        """수집 시작"""
        self.cancel_btn.setEnabled(True)
        self.title_label.setText("Collection in Progress...")

    def _on_collection_completed(self, results: list):
        """수집 완료"""
        self.cancel_btn.setEnabled(False)

        success_count = sum(1 for r in results if r.success)
        total_files = sum(r.collected_count for r in results)

        self.title_label.setText("Collection Completed")
        self.total_files_label.setText(f"{total_files} files collected")
        self._update_device_count()

    def _on_device_started(self, device_id: str):
        """디바이스 수집 시작"""
        if device_id in self.device_cards:
            self.device_cards[device_id].set_status(TaskStatus.RUNNING)

    def _on_device_progress(self, device_id: str, progress: float, artifact: str):
        """디바이스 진행률 업데이트"""
        if device_id in self.device_cards:
            self.device_cards[device_id].set_progress(progress, artifact)
            self._update_overall_progress()

    def _on_device_completed(self, device_id: str, success: bool, message: str):
        """디바이스 수집 완료"""
        if device_id in self.device_cards:
            card = self.device_cards[device_id]
            card.set_status(TaskStatus.COMPLETED if success else TaskStatus.FAILED)
            self._update_device_count()
            self._update_overall_progress()

    def _on_artifact_collected(self, device_id: str, file_path: str):
        """아티팩트 수집됨"""
        if device_id in self.device_cards:
            # 카드의 수집 개수 업데이트
            if self._collector:
                task = self._collector.get_task(device_id)
                if task:
                    self.device_cards[device_id].set_collected_count(
                        len(task.collected_files)
                    )

            # 전체 파일 수 업데이트
            if self._collector:
                total = self._collector.total_collected
                self.total_files_label.setText(f"{total} files collected")

    def _on_error_occurred(self, device_id: str, artifact: str, error: str):
        """에러 발생"""
        if device_id in self.device_cards:
            self.device_cards[device_id].set_error(f"{artifact}: {error}")

    def _on_cancel_clicked(self):
        """취소 버튼 클릭"""
        self.cancel_btn.setEnabled(False)
        self.title_label.setText("Cancelling...")
        self.cancel_requested.emit()

        if self._collector:
            self._collector.cancel()
