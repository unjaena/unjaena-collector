# -*- coding: utf-8 -*-
"""
Multi-Progress Panel

Progress display panel for multiple device collection.

Features:
    - Per-device progress bars
    - Current artifact being collected display
    - Completed/failed status icons
    - Overall progress
    - Cancel button
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
    Individual device progress card.

    Displays device name, progress, current task, and status.
    """

    def __init__(self, device: UnifiedDeviceInfo, parent=None):
        super().__init__(parent)
        self.device = device
        self.device_id = device.device_id
        self._setup_ui()
        self._apply_styles()

    def _setup_ui(self):
        """Setup UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(4)

        # Header row: name + status
        header_layout = QHBoxLayout()
        header_layout.setSpacing(8)

        # Device name
        self.name_label = QLabel(self.device.display_name)
        self.name_label.setFont(QFont("Malgun Gothic", 10, QFont.Weight.Medium))
        header_layout.addWidget(self.name_label, 1)

        # Status icon/text
        self.status_label = QLabel("Pending")
        self.status_label.setObjectName("statusPending")
        self.status_label.setFont(QFont("Malgun Gothic", 9))
        header_layout.addWidget(self.status_label)

        layout.addLayout(header_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        layout.addWidget(self.progress_bar)

        # Detail row: current task + collected count
        detail_layout = QHBoxLayout()
        detail_layout.setSpacing(8)

        self.current_task_label = QLabel("Waiting...")
        self.current_task_label.setObjectName("mutedLabel")
        self.current_task_label.setFont(QFont("Malgun Gothic", 8))
        detail_layout.addWidget(self.current_task_label, 1)

        self.count_label = QLabel("")
        self.count_label.setObjectName("mutedLabel")
        self.count_label.setFont(QFont("Malgun Gothic", 8))
        detail_layout.addWidget(self.count_label)

        layout.addLayout(detail_layout)

    def _apply_styles(self):
        """Apply styles"""
        self.setStyleSheet(f"""
            DeviceProgressCard {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 4px;
            }}
            QLabel {{
                color: {COLORS['text_primary']};
                font-size: 10px;
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
        """Update status"""
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
        self.status_label.setStyleSheet(self.status_label.styleSheet())  # Refresh style

        # Set progress to 100% on completion
        if status == TaskStatus.COMPLETED:
            self.progress_bar.setValue(100)
            self.current_task_label.setText("Done")

    def set_progress(self, progress: float, current_artifact: str = ""):
        """Update progress"""
        self.progress_bar.setValue(int(progress * 100))

        if current_artifact:
            self.current_task_label.setText(f"Collecting: {current_artifact}")

    def set_current_file(self, file_path: str):
        """Update currently collecting file path"""
        if file_path:
            self.current_task_label.setText(f"Collecting: {file_path}")

    def set_collected_count(self, count: int):
        """Update collected count"""
        self.count_label.setText(f"{count} files")

    def set_error(self, error: str):
        """Display error"""
        self.current_task_label.setText(f"Error: {error}")
        self.current_task_label.setStyleSheet(f"color: {COLORS['error']};")


# =============================================================================
# Multi-Progress Panel
# =============================================================================

class MultiProgressPanel(QWidget):
    """
    Multiple device progress panel.

    Shows collection progress for all devices at a glance.

    Signals:
        cancel_requested: Emitted when cancel button is clicked
    """

    cancel_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.device_cards: Dict[str, DeviceProgressCard] = {}
        self._collector: Optional[MultiDeviceCollector] = None
        self._setup_ui()
        self._apply_styles()

    def _setup_ui(self):
        """Setup UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = self._create_header()
        layout.addWidget(header)

        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        # Device cards container
        self.cards_container = QWidget()
        self.cards_layout = QVBoxLayout(self.cards_container)
        self.cards_layout.setContentsMargins(8, 8, 8, 8)
        self.cards_layout.setSpacing(6)
        self.cards_layout.addStretch()

        scroll.setWidget(self.cards_container)
        layout.addWidget(scroll, 1)

        # Footer
        footer = self._create_footer()
        layout.addWidget(footer)

    def _create_header(self) -> QWidget:
        """Create header"""
        header = QWidget()

        layout = QHBoxLayout(header)
        layout.setContentsMargins(8, 6, 8, 6)

        # Title
        self.title_label = QLabel("Collection Progress")
        self.title_label.setObjectName("headerLabel")
        self.title_label.setFont(QFont("Malgun Gothic", 11, QFont.Weight.Medium))
        layout.addWidget(self.title_label)

        layout.addStretch()

        # Device count
        self.device_count_label = QLabel("0/0 devices")
        self.device_count_label.setObjectName("mutedLabel")
        self.device_count_label.setFont(QFont("Malgun Gothic", 9))
        layout.addWidget(self.device_count_label)

        return header

    def _create_footer(self) -> QWidget:
        """Create footer"""
        footer = QWidget()

        layout = QVBoxLayout(footer)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(6)

        # Overall progress
        progress_layout = QHBoxLayout()
        progress_layout.setSpacing(8)

        progress_label = QLabel("Overall:")
        progress_label.setFont(QFont("Malgun Gothic", 9))
        progress_layout.addWidget(progress_label)

        self.overall_progress = QProgressBar()
        self.overall_progress.setRange(0, 100)
        self.overall_progress.setValue(0)
        self.overall_progress.setObjectName("largeProgress")
        self.overall_progress.setFixedHeight(8)
        progress_layout.addWidget(self.overall_progress, 1)

        self.overall_percent_label = QLabel("0%")
        self.overall_percent_label.setFixedWidth(35)
        self.overall_percent_label.setFont(QFont("Malgun Gothic", 9))
        progress_layout.addWidget(self.overall_percent_label)

        layout.addLayout(progress_layout)

        # Button area
        button_layout = QHBoxLayout()
        button_layout.setSpacing(8)

        # Collected file count
        self.total_files_label = QLabel("0 files collected")
        self.total_files_label.setObjectName("mutedLabel")
        self.total_files_label.setFont(QFont("Malgun Gothic", 9))
        button_layout.addWidget(self.total_files_label)

        button_layout.addStretch()

        # Cancel button
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("dangerButton")
        self.cancel_btn.setFixedHeight(24)
        self.cancel_btn.clicked.connect(self._on_cancel_clicked)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)

        return footer

    def _apply_styles(self):
        """Apply styles"""
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
        """Bind collector"""
        self._collector = collector

        # Connect signals
        collector.collection_started.connect(self._on_collection_started)
        collector.collection_completed.connect(self._on_collection_completed)
        collector.device_started.connect(self._on_device_started)
        collector.device_progress.connect(self._on_device_progress)
        collector.device_completed.connect(self._on_device_completed)
        collector.artifact_collected.connect(self._on_artifact_collected)
        collector.error_occurred.connect(self._on_error_occurred)

    def add_device(self, device: UnifiedDeviceInfo):
        """Add device card"""
        if device.device_id in self.device_cards:
            return

        card = DeviceProgressCard(device)
        self.device_cards[device.device_id] = card

        # Insert before stretch
        self.cards_layout.insertWidget(
            self.cards_layout.count() - 1,  # Before stretch
            card
        )

        self._update_device_count()

    def clear(self):
        """Remove all cards"""
        for card in self.device_cards.values():
            self.cards_layout.removeWidget(card)
            card.deleteLater()

        self.device_cards.clear()
        self.overall_progress.setValue(0)
        self.overall_percent_label.setText("0%")
        self.total_files_label.setText("0 files collected")
        self._update_device_count()

    def _update_device_count(self):
        """Update device count"""
        completed = sum(
            1 for card in self.device_cards.values()
            if card.status_label.text() in ("Completed", "Failed")
        )
        total = len(self.device_cards)
        self.device_count_label.setText(f"{completed}/{total} devices")

    def _update_overall_progress(self):
        """Update overall progress"""
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
        """Collection started"""
        self.cancel_btn.setEnabled(True)
        self.title_label.setText("Collection in Progress...")

    def _on_collection_completed(self, results: list):
        """Collection completed"""
        self.cancel_btn.setEnabled(False)

        success_count = sum(1 for r in results if r.success)
        total_files = sum(r.collected_count for r in results)

        self.title_label.setText("Collection Completed")
        self.total_files_label.setText(f"{total_files} files collected")
        self._update_device_count()

    def _on_device_started(self, device_id: str):
        """Device collection started"""
        if device_id in self.device_cards:
            self.device_cards[device_id].set_status(TaskStatus.RUNNING)

    def _on_device_progress(self, device_id: str, progress: float, artifact: str):
        """Device progress update"""
        if device_id in self.device_cards:
            self.device_cards[device_id].set_progress(progress, artifact)
            self._update_overall_progress()

    def _on_device_completed(self, device_id: str, success: bool, message: str):
        """Device collection completed"""
        if device_id in self.device_cards:
            card = self.device_cards[device_id]
            card.set_status(TaskStatus.COMPLETED if success else TaskStatus.FAILED)
            self._update_device_count()
            self._update_overall_progress()

    def _on_artifact_collected(self, device_id: str, file_path: str):
        """Artifact collected"""
        if device_id in self.device_cards:
            card = self.device_cards[device_id]

            # Display currently collecting file path
            card.set_current_file(file_path)

            # Update card collected count
            if self._collector:
                task = self._collector.get_task(device_id)
                if task:
                    card.set_collected_count(len(task.collected_files))

            # Update total file count
            if self._collector:
                total = self._collector.total_collected
                self.total_files_label.setText(f"{total} files collected")

    def _on_error_occurred(self, device_id: str, artifact: str, error: str):
        """Error occurred"""
        if device_id in self.device_cards:
            self.device_cards[device_id].set_error(f"{artifact}: {error}")

    def _on_cancel_clicked(self):
        """Cancel button clicked"""
        self.cancel_btn.setEnabled(False)
        self.title_label.setText("Cancelling...")
        self.cancel_requested.emit()

        if self._collector:
            self._collector.cancel()
