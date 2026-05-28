# -*- coding: utf-8 -*-
"""
LUKS Decryption Dialog

Dialog that prompts the user to enter passphrase when a LUKS encrypted volume is detected.
"""
from dataclasses import dataclass
from typing import Optional

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QMessageBox, QGroupBox
)
from PyQt6.QtCore import Qt

from gui.styles import COLORS


@dataclass
class LUKSDialogResult:
    """LUKS dialog result"""
    success: bool = False
    passphrase: str = ""
    skip: bool = False


class LUKSDialog(QDialog):
    """LUKS encrypted volume passphrase input dialog"""

    def __init__(
        self,
        partition_info: dict = None,
        fve_available: bool = True,
        parent=None
    ):
        """
        Args:
            partition_info: LUKS partition information
                - partition_index: Partition index
                - partition_offset: Offset
                - partition_size: Size
                - luks_version: LUKS version (1 or 2)
            fve_available: Whether dissect.fve is installed
            parent: Parent widget
        """
        super().__init__(parent)
        self.partition_info = partition_info or {}
        self.fve_available = fve_available
        self.result = LUKSDialogResult()
        self.setup_ui()

    def setup_ui(self):
        """Initialize UI"""
        self.setWindowTitle("LUKS Encrypted Volume Detected")
        self.setMinimumSize(480, 360)
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 16, 16, 16)

        # Header
        header = QLabel("LUKS Encrypted Volume Detected")
        header.setObjectName("header")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Info banner
        info_frame = QFrame()
        info_frame.setObjectName("infoFrame")
        info_layout = QVBoxLayout(info_frame)

        info_text = (
            "A LUKS encrypted volume has been detected.\n"
            "Enter the passphrase to collect artifacts from the encrypted data."
        )
        info_label = QLabel(info_text)
        info_label.setObjectName("infoText")
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)

        # Partition info display
        if self.partition_info:
            partition_text = self._format_partition_info()
            partition_label = QLabel(partition_text)
            partition_label.setObjectName("partitionInfo")
            info_layout.addWidget(partition_label)

        layout.addWidget(info_frame)

        # fve not installed warning
        if not self.fve_available:
            warning_frame = QFrame()
            warning_frame.setObjectName("warningFrame")
            warning_layout = QHBoxLayout(warning_frame)
            warning_label = QLabel(
                "Warning: Decryption library is not installed.\n"
                "Installation is required to use LUKS decryption:\n"
                "pip install dissect.fve"
            )
            warning_label.setObjectName("warningText")
            warning_label.setWordWrap(True)
            warning_layout.addWidget(warning_label)
            layout.addWidget(warning_frame)

        # Passphrase input
        input_frame = QFrame()
        input_frame.setObjectName("inputFrame")
        input_layout = QVBoxLayout(input_frame)

        passphrase_label = QLabel("Passphrase:")
        input_layout.addWidget(passphrase_label)

        key_row = QHBoxLayout()
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setPlaceholderText("Enter LUKS passphrase")
        self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase_input.setEnabled(self.fve_available)
        key_row.addWidget(self.passphrase_input)

        self.show_key_btn = QPushButton("Show")
        self.show_key_btn.setFixedWidth(60)
        self.show_key_btn.setCheckable(True)
        self.show_key_btn.toggled.connect(self._toggle_visibility)
        key_row.addWidget(self.show_key_btn)

        input_layout.addLayout(key_row)

        # Error message area
        self.error_label = QLabel("")
        self.error_label.setObjectName("errorLabel")
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        input_layout.addWidget(self.error_label)

        layout.addWidget(input_frame)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.skip_btn = QPushButton("Skip (Collect Encrypted)")
        self.skip_btn.clicked.connect(self._on_skip)
        self.skip_btn.setMinimumWidth(180)
        button_layout.addWidget(self.skip_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setMinimumWidth(80)
        button_layout.addWidget(self.cancel_btn)

        self.unlock_btn = QPushButton("Unlock")
        self.unlock_btn.setObjectName("unlockButton")
        self.unlock_btn.setEnabled(self.fve_available)
        self.unlock_btn.clicked.connect(self._on_unlock)
        self.unlock_btn.setMinimumWidth(100)
        button_layout.addWidget(self.unlock_btn)

        layout.addLayout(button_layout)

    def _format_partition_info(self) -> str:
        """Format partition info"""
        info = self.partition_info
        size_gb = info.get('partition_size', 0) / (1024 ** 3)

        text = f"Partition #{info.get('partition_index', 0)}"
        if size_gb > 0:
            text += f" | Size: {size_gb:.1f} GB"
        luks_ver = info.get('luks_version')
        if luks_ver:
            text += f" | LUKS{luks_ver}"

        return text

    def _toggle_visibility(self, checked: bool):
        if checked:
            self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_key_btn.setText("Hide")
        else:
            self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_key_btn.setText("Show")

    def _on_unlock(self):
        passphrase = self.passphrase_input.text()
        if not passphrase:
            self.error_label.setText("Please enter a passphrase.")
            self.error_label.show()
            return

        self.result.success = True
        self.result.passphrase = passphrase
        self.result.skip = False
        self.accept()

    def _on_skip(self):
        reply = QMessageBox.question(
            self,
            "Skip LUKS",
            "Skipping LUKS decryption will collect data in encrypted state.\n"
            "Some artifacts may not be extractable.\n\n"
            "Do you want to continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.result.success = False
            self.result.skip = True
            self.accept()

    def get_result(self) -> LUKSDialogResult:
        return self.result

    def _get_stylesheet(self) -> str:
        return f"""
            QDialog {{
                background-color: {COLORS['bg_primary']};
            }}
            #header {{
                font-size: 16px;
                font-weight: bold;
                color: {COLORS['warning']};
                padding: 4px;
            }}
            #infoFrame {{
                background-color: {COLORS['info_bg']};
                border: 1px solid {COLORS['info']};
                border-radius: 6px;
                padding: 8px;
            }}
            #infoText {{
                color: {COLORS['text_primary']};
                font-size: 11px;
            }}
            #partitionInfo {{
                color: {COLORS['info']};
                font-size: 10px;
                font-weight: bold;
                margin-top: 4px;
            }}
            #warningFrame {{
                background-color: {COLORS['error_bg']};
                border: 1px solid {COLORS['error']};
                border-radius: 6px;
                padding: 8px;
            }}
            #warningText {{
                color: {COLORS['error']};
                font-size: 10px;
            }}
            #inputFrame {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 6px;
                padding: 8px;
            }}
            QLineEdit {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 4px;
                color: {COLORS['text_primary']};
                padding: 6px;
                font-size: 11px;
            }}
            QLineEdit:disabled {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_tertiary']};
            }}
            QLabel {{
                color: {COLORS['text_primary']};
                font-size: 11px;
            }}
            #errorLabel {{
                color: {COLORS['error']};
                font-size: 10px;
                padding: 4px;
                background-color: {COLORS['error_bg']};
                border-radius: 4px;
            }}
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 4px;
                color: {COLORS['text_primary']};
                padding: 6px 12px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['bg_hover']};
                border-color: {COLORS['border_default']};
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_tertiary']};
            }}
            #unlockButton {{
                background-color: {COLORS['brand_primary']};
                border: none;
                color: {COLORS['bg_primary']};
                font-weight: bold;
            }}
            #unlockButton:hover {{
                background-color: {COLORS['brand_accent']};
            }}
            #unlockButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_tertiary']};
            }}
        """


def show_luks_dialog(
    partition_info: dict = None,
    fve_available: bool = True,
    parent=None
) -> LUKSDialogResult:
    """
    Display LUKS dialog and return result.

    Args:
        partition_info: Partition information
        fve_available: Whether dissect.fve is installed
        parent: Parent widget

    Returns:
        LUKSDialogResult
    """
    dialog = LUKSDialog(
        partition_info=partition_info,
        fve_available=fve_available,
        parent=parent
    )
    result_code = dialog.exec()

    if result_code == QDialog.DialogCode.Accepted:
        return dialog.get_result()

    return LUKSDialogResult(success=False, skip=False)
