# -*- coding: utf-8 -*-
"""
E01 Selection Dialog

Dialog for E01 evidence image selection and partition preview.

Features:
    - E01/RAW image file selection
    - Partition list display
    - Image information preview
"""

import logging
import os
import sys
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
    """Partition analysis worker thread"""

    analysis_complete = pyqtSignal(list)  # Partition info list
    analysis_failed = pyqtSignal(str)     # Error message
    progress_update = pyqtSignal(str)     # Progress status message

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path

    def run(self):
        """Execute partition analysis"""
        temp_dir = None
        try:
            self.progress_update.emit("Loading image...")

            from collectors.e01_artifact_collector import E01ArtifactCollector

            # Use temporary directory (to avoid including E01 file in local collection)
            temp_dir = tempfile.mkdtemp(prefix="e01_preview_")
            if sys.platform != 'win32':
                os.chmod(temp_dir, 0o700)  # Unix: owner-only access
            collector = E01ArtifactCollector(self.file_path, output_dir=temp_dir)

            self.progress_update.emit("Analyzing partitions...")
            partitions = collector.list_partitions()

            collector.close()

            self.analysis_complete.emit(partitions)

        except Exception as e:
            logger.error(f"Partition analysis failed: {e}")
            self.analysis_failed.emit(str(e))

        finally:
            # Clean up temporary directory
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
    E01 image selection dialog.

    Allows users to select E01/RAW images and preview partition information.

    Usage:
        dialog = E01SelectionDialog(parent)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            file_path = dialog.get_selected_path()
    """

    # Supported extensions
    SUPPORTED_EXTENSIONS = "*.E01 *.e01 *.Ex01 *.ex01 *.dd *.raw *.img *.bin"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_path: Optional[str] = None
        self.partitions: List[Dict[str, Any]] = []
        self._analyzer: Optional[PartitionAnalyzer] = None

        self._setup_ui()
        self._apply_styles()

    def _setup_ui(self):
        """Setup UI"""
        self.setWindowTitle("Add Forensic Image")
        self.setMinimumSize(650, 500)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # File selection section
        file_group = self._create_file_section()
        layout.addWidget(file_group)

        # Image information section
        info_group = self._create_info_section()
        layout.addWidget(info_group)

        # Partition list section
        partition_group = self._create_partition_section()
        layout.addWidget(partition_group, 1)

        # Button area
        button_layout = self._create_button_section()
        layout.addLayout(button_layout)

    def _create_file_section(self) -> QGroupBox:
        """Create file selection section"""
        group = QGroupBox("Select Forensic Image")

        layout = QVBoxLayout(group)

        # File selection button
        btn_layout = QHBoxLayout()

        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.clicked.connect(self._on_browse_clicked)
        btn_layout.addWidget(self.browse_btn)

        btn_layout.addStretch()

        layout.addLayout(btn_layout)

        # Selected file path
        self.file_label = QLabel("No file selected")
        self.file_label.setObjectName("mutedLabel")
        self.file_label.setWordWrap(True)
        layout.addWidget(self.file_label)

        # Progress indicator
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("")
        self.status_label.setObjectName("mutedLabel")
        self.status_label.setVisible(False)
        layout.addWidget(self.status_label)

        return group

    def _create_info_section(self) -> QGroupBox:
        """Create image information section"""
        group = QGroupBox("Image Information")

        layout = QHBoxLayout(group)

        # Info labels
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
        """Create information row"""
        layout = QHBoxLayout()
        layout.setSpacing(12)

        label_widget = QLabel(label)
        label_widget.setObjectName("mutedLabel")
        label_widget.setFixedWidth(80)
        layout.addWidget(label_widget)

        value_widget = QLabel(value)
        value_widget.setObjectName("value")
        layout.addWidget(value_widget, 1)

        # Store reference to value widget
        layout.value_widget = value_widget

        return layout

    def _create_partition_section(self) -> QGroupBox:
        """Create partition list section"""
        group = QGroupBox("Detected Partitions")

        layout = QVBoxLayout(group)

        # Table
        self.partition_table = QTableWidget()
        self.partition_table.setColumnCount(5)
        self.partition_table.setHorizontalHeaderLabels([
            "Index", "Filesystem", "Size", "Type", "Status"
        ])

        # Adjust column sizes
        header = self.partition_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)

        self.partition_table.setColumnWidth(0, 60)
        self.partition_table.setColumnWidth(2, 100)
        self.partition_table.setColumnWidth(4, 80)

        # Selection mode
        self.partition_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.partition_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)

        layout.addWidget(self.partition_table)

        # Empty state message
        self.empty_label = QLabel("Select an image file to view partitions")
        self.empty_label.setObjectName("mutedLabel")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.empty_label)

        return group

    def _create_button_section(self) -> QHBoxLayout:
        """Create button area"""
        layout = QHBoxLayout()

        layout.addStretch()

        # Cancel button
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        layout.addWidget(cancel_btn)

        # Add button
        self.add_btn = QPushButton("Add Image")
        self.add_btn.setObjectName("primaryButton")
        self.add_btn.setEnabled(False)
        self.add_btn.clicked.connect(self.accept)
        layout.addWidget(self.add_btn)

        return layout

    def _apply_styles(self):
        """Apply styles"""
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
        """Browse button clicked"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Forensic Image",
            "",
            f"Forensic Images ({self.SUPPORTED_EXTENSIONS});;All Files (*)"
        )

        if file_path:
            self._load_image(file_path)

    def _load_image(self, file_path: str):
        """Load and analyze image"""
        path = Path(file_path)

        # Display file info
        self.file_label.setText(str(path))
        self.file_label.setObjectName("")  # Reset style

        # Image type
        ext = path.suffix.lower()
        if ext in ('.e01', '.ex01'):
            image_type = "E01 (EnCase)"
        elif ext in ('.dd', '.raw', '.img', '.bin'):
            image_type = "RAW/DD"
        else:
            image_type = "Unknown"

        # File size
        try:
            size = path.stat().st_size
            size_display = self._format_size(size)
        except:
            size_display = "Unknown"

        # Update info
        self.info_labels['type'].value_widget.setText(image_type)
        self.info_labels['size'].value_widget.setText(size_display)
        self.info_labels['partitions'].value_widget.setText("Analyzing...")

        # Progress display
        self.progress_bar.setVisible(True)
        self.status_label.setVisible(True)
        self.status_label.setText("Loading image...")
        self.add_btn.setEnabled(False)

        # Start partition analysis
        self._analyzer = PartitionAnalyzer(file_path)
        self._analyzer.analysis_complete.connect(self._on_analysis_complete)
        self._analyzer.analysis_failed.connect(self._on_analysis_failed)
        self._analyzer.progress_update.connect(self._on_progress_update)
        self._analyzer.start()

        self.selected_path = file_path

    def _on_analysis_complete(self, partitions: list):
        """Partition analysis complete"""
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(False)
        self.partitions = partitions

        # Update info
        self.info_labels['partitions'].value_widget.setText(str(len(partitions)))

        # Update table
        self._update_partition_table(partitions)

        # Enable button
        self.add_btn.setEnabled(True)
        self.empty_label.setVisible(False)

    def _on_analysis_failed(self, error: str):
        """Partition analysis failed"""
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
        """Progress status update"""
        self.status_label.setText(message)

    def _update_partition_table(self, partitions: list):
        """Update partition table"""
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

        # Select first NTFS partition
        for row in range(len(partitions)):
            if getattr(partitions[row], 'filesystem', '').upper() == 'NTFS':
                self.partition_table.selectRow(row)
                break

    def get_selected_path(self) -> Optional[str]:
        """Return selected image path"""
        return self.selected_path

    def get_selected_partition(self) -> Optional[int]:
        """Return selected partition index"""
        selected = self.partition_table.selectedItems()
        if selected:
            row = selected[0].row()
            return row
        return None

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format size"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"

    def closeEvent(self, event):
        """Dialog close event"""
        if self._analyzer and self._analyzer.isRunning():
            self._analyzer.terminate()
            self._analyzer.wait()
        super().closeEvent(event)
