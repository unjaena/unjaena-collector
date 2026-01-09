# -*- coding: utf-8 -*-
"""
E01 Selection Dialog

E01 증거 이미지 선택 및 파티션 미리보기 대화상자.

Features:
    - E01/RAW 이미지 파일 선택
    - 파티션 목록 표시
    - 이미지 정보 미리보기
"""

import logging
import tempfile
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QProgressBar, QMessageBox, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from gui.styles import COLORS

logger = logging.getLogger(__name__)


# =============================================================================
# Partition Analysis Worker
# =============================================================================

class PartitionAnalyzer(QThread):
    """파티션 분석 워커 스레드"""

    analysis_complete = pyqtSignal(list)  # 파티션 정보 리스트
    analysis_failed = pyqtSignal(str)     # 에러 메시지
    progress_update = pyqtSignal(str)     # 진행 상태 메시지

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path

    def run(self):
        """파티션 분석 실행"""
        temp_dir = None
        try:
            self.progress_update.emit("Loading image...")

            from collectors.e01_artifact_collector import E01ArtifactCollector

            # 임시 디렉토리 사용 (로컬 수집 시 E01 파일이 포함되지 않도록)
            temp_dir = tempfile.mkdtemp(prefix="e01_preview_")
            collector = E01ArtifactCollector(self.file_path, output_dir=temp_dir)

            self.progress_update.emit("Analyzing partitions...")
            partitions = collector.list_partitions()

            collector.close()

            self.analysis_complete.emit(partitions)

        except Exception as e:
            logger.error(f"Partition analysis failed: {e}")
            self.analysis_failed.emit(str(e))

        finally:
            # 임시 디렉토리 정리
            if temp_dir and Path(temp_dir).exists():
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp directory: {e}")


# =============================================================================
# E01 Selection Dialog
# =============================================================================

class E01SelectionDialog(QDialog):
    """
    E01 이미지 선택 대화상자

    사용자가 E01/RAW 이미지를 선택하고 파티션 정보를 미리보기할 수 있습니다.

    Usage:
        dialog = E01SelectionDialog(parent)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            file_path = dialog.get_selected_path()
    """

    # 지원하는 확장자
    SUPPORTED_EXTENSIONS = "*.E01 *.e01 *.Ex01 *.ex01 *.dd *.raw *.img *.bin"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_path: Optional[str] = None
        self.partitions: List[Dict[str, Any]] = []
        self._analyzer: Optional[PartitionAnalyzer] = None

        self._setup_ui()
        self._apply_styles()

    def _setup_ui(self):
        """UI 구성"""
        self.setWindowTitle("Add Forensic Image")
        self.setMinimumSize(650, 500)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # 파일 선택 섹션
        file_group = self._create_file_section()
        layout.addWidget(file_group)

        # 이미지 정보 섹션
        info_group = self._create_info_section()
        layout.addWidget(info_group)

        # 파티션 목록 섹션
        partition_group = self._create_partition_section()
        layout.addWidget(partition_group, 1)

        # 버튼 영역
        button_layout = self._create_button_section()
        layout.addLayout(button_layout)

    def _create_file_section(self) -> QGroupBox:
        """파일 선택 섹션"""
        group = QGroupBox("Select Forensic Image")

        layout = QVBoxLayout(group)

        # 파일 선택 버튼
        btn_layout = QHBoxLayout()

        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.clicked.connect(self._on_browse_clicked)
        btn_layout.addWidget(self.browse_btn)

        btn_layout.addStretch()

        layout.addLayout(btn_layout)

        # 선택된 파일 경로
        self.file_label = QLabel("No file selected")
        self.file_label.setObjectName("mutedLabel")
        self.file_label.setWordWrap(True)
        layout.addWidget(self.file_label)

        # 진행 표시
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # 무한 진행
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("")
        self.status_label.setObjectName("mutedLabel")
        self.status_label.setVisible(False)
        layout.addWidget(self.status_label)

        return group

    def _create_info_section(self) -> QGroupBox:
        """이미지 정보 섹션"""
        group = QGroupBox("Image Information")

        layout = QHBoxLayout(group)

        # 정보 라벨들
        info_frame = QFrame()
        info_layout = QVBoxLayout(info_frame)
        info_layout.setSpacing(8)

        self.info_labels = {
            'type': self._create_info_row("Type:", "-"),
            'size': self._create_info_row("Size:", "-"),
            'partitions': self._create_info_row("Partitions:", "-"),
        }

        for row in self.info_labels.values():
            info_layout.addLayout(row)

        layout.addWidget(info_frame)
        layout.addStretch()

        return group

    def _create_info_row(self, label: str, value: str) -> QHBoxLayout:
        """정보 행 생성"""
        layout = QHBoxLayout()
        layout.setSpacing(12)

        label_widget = QLabel(label)
        label_widget.setObjectName("mutedLabel")
        label_widget.setFixedWidth(80)
        layout.addWidget(label_widget)

        value_widget = QLabel(value)
        value_widget.setObjectName("value")
        layout.addWidget(value_widget, 1)

        # value 위젯에 대한 참조 저장
        layout.value_widget = value_widget

        return layout

    def _create_partition_section(self) -> QGroupBox:
        """파티션 목록 섹션"""
        group = QGroupBox("Detected Partitions")

        layout = QVBoxLayout(group)

        # 테이블
        self.partition_table = QTableWidget()
        self.partition_table.setColumnCount(5)
        self.partition_table.setHorizontalHeaderLabels([
            "Index", "Filesystem", "Size", "Type", "Status"
        ])

        # 열 크기 조정
        header = self.partition_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)

        self.partition_table.setColumnWidth(0, 60)
        self.partition_table.setColumnWidth(2, 100)
        self.partition_table.setColumnWidth(4, 80)

        # 선택 모드
        self.partition_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.partition_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)

        layout.addWidget(self.partition_table)

        # 빈 상태 메시지
        self.empty_label = QLabel("Select an image file to view partitions")
        self.empty_label.setObjectName("mutedLabel")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.empty_label)

        return group

    def _create_button_section(self) -> QHBoxLayout:
        """버튼 영역"""
        layout = QHBoxLayout()

        layout.addStretch()

        # 취소 버튼
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        layout.addWidget(cancel_btn)

        # 추가 버튼
        self.add_btn = QPushButton("Add Image")
        self.add_btn.setObjectName("primaryButton")
        self.add_btn.setEnabled(False)
        self.add_btn.clicked.connect(self.accept)
        layout.addWidget(self.add_btn)

        return layout

    def _apply_styles(self):
        """스타일 적용"""
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_primary']};
            }}
            QGroupBox {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 8px;
                margin-top: 16px;
                padding: 16px;
                padding-top: 24px;
                font-weight: 500;
                color: {COLORS['text_primary']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 12px;
                padding: 0 8px;
                background-color: {COLORS['bg_secondary']};
            }}
            QLabel {{
                color: {COLORS['text_primary']};
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
                min-width: 80px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['bg_hover']};
            }}
            QPushButton#primaryButton {{
                background-color: {COLORS['brand_primary']};
                border: none;
                color: {COLORS['bg_primary']};
            }}
            QPushButton#primaryButton:hover {{
                background-color: {COLORS['brand_accent']};
            }}
            QPushButton#primaryButton:disabled {{
                background-color: {COLORS['bg_hover']};
                color: {COLORS['text_tertiary']};
            }}
            QTableWidget {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 6px;
                gridline-color: {COLORS['border_subtle']};
            }}
            QTableWidget::item {{
                padding: 8px;
                color: {COLORS['text_primary']};
            }}
            QTableWidget::item:selected {{
                background-color: rgba(212, 165, 116, 0.2);
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_secondary']};
                padding: 8px;
                border: none;
                border-bottom: 1px solid {COLORS['border_subtle']};
            }}
            QProgressBar {{
                background-color: {COLORS['bg_tertiary']};
                border: none;
                border-radius: 4px;
                height: 6px;
            }}
            QProgressBar::chunk {{
                background-color: {COLORS['brand_primary']};
                border-radius: 4px;
            }}
        """)

    def _on_browse_clicked(self):
        """파일 선택 버튼 클릭"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Forensic Image",
            "",
            f"Forensic Images ({self.SUPPORTED_EXTENSIONS});;All Files (*)"
        )

        if file_path:
            self._load_image(file_path)

    def _load_image(self, file_path: str):
        """이미지 로드 및 분석"""
        path = Path(file_path)

        # 파일 정보 표시
        self.file_label.setText(str(path))
        self.file_label.setObjectName("")  # 스타일 리셋

        # 이미지 유형
        ext = path.suffix.lower()
        if ext in ('.e01', '.ex01'):
            image_type = "E01 (EnCase)"
        elif ext in ('.dd', '.raw', '.img', '.bin'):
            image_type = "RAW/DD"
        else:
            image_type = "Unknown"

        # 파일 크기
        try:
            size = path.stat().st_size
            size_display = self._format_size(size)
        except:
            size_display = "Unknown"

        # 정보 업데이트
        self.info_labels['type'].value_widget.setText(image_type)
        self.info_labels['size'].value_widget.setText(size_display)
        self.info_labels['partitions'].value_widget.setText("Analyzing...")

        # 진행 표시
        self.progress_bar.setVisible(True)
        self.status_label.setVisible(True)
        self.status_label.setText("Loading image...")
        self.add_btn.setEnabled(False)

        # 파티션 분석 시작
        self._analyzer = PartitionAnalyzer(file_path)
        self._analyzer.analysis_complete.connect(self._on_analysis_complete)
        self._analyzer.analysis_failed.connect(self._on_analysis_failed)
        self._analyzer.progress_update.connect(self._on_progress_update)
        self._analyzer.start()

        self.selected_path = file_path

    def _on_analysis_complete(self, partitions: list):
        """파티션 분석 완료"""
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(False)
        self.partitions = partitions

        # 정보 업데이트
        self.info_labels['partitions'].value_widget.setText(str(len(partitions)))

        # 테이블 업데이트
        self._update_partition_table(partitions)

        # 버튼 활성화
        self.add_btn.setEnabled(True)
        self.empty_label.setVisible(False)

    def _on_analysis_failed(self, error: str):
        """파티션 분석 실패"""
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(True)
        self.status_label.setText(f"Error: {error}")
        self.status_label.setStyleSheet(f"color: {COLORS['error']};")

        self.info_labels['partitions'].value_widget.setText("Failed")
        self.add_btn.setEnabled(False)

        QMessageBox.warning(
            self,
            "Analysis Failed",
            f"Failed to analyze image:\n{error}"
        )

    def _on_progress_update(self, message: str):
        """진행 상태 업데이트"""
        self.status_label.setText(message)

    def _update_partition_table(self, partitions: list):
        """파티션 테이블 업데이트"""
        self.partition_table.setRowCount(len(partitions))

        for row, p in enumerate(partitions):
            # Index
            index_item = QTableWidgetItem(str(p.get('index', row)))
            index_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.partition_table.setItem(row, 0, index_item)

            # Filesystem
            fs_item = QTableWidgetItem(p.get('filesystem', 'Unknown'))
            self.partition_table.setItem(row, 1, fs_item)

            # Size
            size_item = QTableWidgetItem(p.get('size_display', '-'))
            size_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.partition_table.setItem(row, 2, size_item)

            # Type
            type_item = QTableWidgetItem(p.get('type', 'Unknown'))
            self.partition_table.setItem(row, 3, type_item)

            # Status
            status = "Ready" if p.get('filesystem', '').upper() == 'NTFS' else "Limited"
            status_item = QTableWidgetItem(status)
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.partition_table.setItem(row, 4, status_item)

        # 첫 번째 NTFS 파티션 선택
        for row in range(len(partitions)):
            if getattr(partitions[row], 'filesystem', '').upper() == 'NTFS':
                self.partition_table.selectRow(row)
                break

    def get_selected_path(self) -> Optional[str]:
        """선택된 이미지 경로 반환"""
        return self.selected_path

    def get_selected_partition(self) -> Optional[int]:
        """선택된 파티션 인덱스 반환"""
        selected = self.partition_table.selectedItems()
        if selected:
            row = selected[0].row()
            return row
        return None

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """크기 포맷팅"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"

    def closeEvent(self, event):
        """대화상자 닫기"""
        if self._analyzer and self._analyzer.isRunning():
            self._analyzer.terminate()
            self._analyzer.wait()
        super().closeEvent(event)
