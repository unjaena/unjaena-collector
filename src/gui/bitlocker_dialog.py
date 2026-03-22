# -*- coding: utf-8 -*-
"""
BitLocker Decryption Dialog

Dialog that prompts the user to enter decryption key when a BitLocker encrypted volume is detected.
"""
from dataclasses import dataclass
from typing import Optional
import os
import re

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QRadioButton, QButtonGroup,
    QFileDialog, QMessageBox, QGroupBox,
)
from PyQt6.QtCore import Qt

from gui.styles import COLORS


@dataclass
class BitLockerDialogResult:
    """BitLocker dialog result"""
    success: bool = False
    key_type: str = ""          # 'recovery_password' | 'password' | 'bek_file' | 'auto_decrypt'
    key_value: str = ""         # Recovery password or password
    bek_path: str = ""          # BEK file path
    skip: bool = False          # Skip (proceed without decryption)
    auto_decrypt: bool = False  # manage-bde auto-decrypt mode


class BitLockerDialog(QDialog):
    """BitLocker decryption key input dialog"""

    # Recovery key format: 8 groups of 6 digits separated by hyphens
    _RECOVERY_KEY_PATTERN = r'^\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}$'

    def __init__(
        self,
        partition_info: dict = None,
        pybde_available: bool = True,
        config: dict = None,
        parent=None
    ):
        """
        Args:
            partition_info: BitLocker partition information
                - partition_index: Partition index
                - partition_offset: Offset
                - partition_size: Size
                - encryption_method: Encryption method
            pybde_available: Whether pybde is installed
            config: Application config (for dev_mode flag)
            parent: Parent widget
        """
        super().__init__(parent)
        self.partition_info = partition_info or {}
        self.pybde_available = pybde_available
        self._dev_mode = config.get('dev_mode', False) if config else False
        self.result = BitLockerDialogResult()
        self.setup_ui()

    def setup_ui(self):
        """Initialize UI"""
        self.setWindowTitle("BitLocker Volume Detected")
        self.setMinimumSize(520, 580)
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 16, 16, 16)

        # Header
        header = QLabel("BitLocker Encrypted Volume Detected")
        header.setObjectName("header")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Info banner
        info_frame = QFrame()
        info_frame.setObjectName("infoFrame")
        info_layout = QVBoxLayout(info_frame)

        info_text = (
            "A BitLocker encrypted volume has been detected on the system.\n"
            "Enter the decryption key to collect artifacts from the encrypted data."
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

        # pybde not installed warning
        if not self.pybde_available:
            warning_frame = QFrame()
            warning_frame.setObjectName("warningFrame")
            warning_layout = QHBoxLayout(warning_frame)
            warning_label = QLabel(
                "Warning: Decryption library is not installed.\n"
                "Installation is required to use BitLocker decryption:\n"
                "pip install dissect.fve"
            )
            warning_label.setObjectName("warningText")
            warning_label.setWordWrap(True)
            warning_layout.addWidget(warning_label)
            layout.addWidget(warning_frame)

        # Key type selection
        key_group = QGroupBox("Select Decryption Key Type")
        key_group.setObjectName("keyGroup")
        key_layout = QVBoxLayout(key_group)

        self.key_type_group = QButtonGroup(self)

        # Recovery Password option
        self.radio_recovery = QRadioButton("Recovery Key (Recovery Password)")
        self.radio_recovery.setChecked(True)
        self.radio_recovery.setEnabled(self.pybde_available)
        self.key_type_group.addButton(self.radio_recovery)
        key_layout.addWidget(self.radio_recovery)

        recovery_desc = QLabel(
            "   48-digit number (e.g., 123456-234567-345678-456789-567890-678901-789012-890123)"
        )
        recovery_desc.setObjectName("keyDesc")
        recovery_desc.setWordWrap(True)
        key_layout.addWidget(recovery_desc)

        # Password option
        self.radio_password = QRadioButton("Password")
        self.radio_password.setEnabled(self.pybde_available)
        self.key_type_group.addButton(self.radio_password)
        key_layout.addWidget(self.radio_password)

        password_desc = QLabel("   Password entered when BitLocker was configured")
        password_desc.setObjectName("keyDesc")
        key_layout.addWidget(password_desc)

        # BEK File option
        self.radio_bek = QRadioButton("Startup Key File (BEK File)")
        self.radio_bek.setEnabled(self.pybde_available)
        self.key_type_group.addButton(self.radio_bek)
        key_layout.addWidget(self.radio_bek)

        bek_desc = QLabel("   .BEK file stored on USB drive or similar")
        bek_desc.setObjectName("keyDesc")
        key_layout.addWidget(bek_desc)

        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setStyleSheet(f"background-color: {COLORS['border_subtle']};")
        key_layout.addWidget(separator)

        # Auto-decrypt option (manage-bde)
        self.radio_auto_decrypt = QRadioButton("Auto-Decrypt and Collect (manage-bde)")
        self.radio_auto_decrypt.setEnabled(True)  # Always available (Windows built-in)
        self.key_type_group.addButton(self.radio_auto_decrypt)
        key_layout.addWidget(self.radio_auto_decrypt)

        auto_desc = QLabel(
            "   Warning: Temporarily disables system BitLocker, re-encrypts after collection\n"
            "   - Administrator privileges required\n"
            "   - May take several minutes to hours depending on disk size"
        )
        auto_desc.setObjectName("keyDesc")
        auto_desc.setWordWrap(True)
        key_layout.addWidget(auto_desc)

        layout.addWidget(key_group)

        # Input field area
        input_frame = QFrame()
        input_frame.setObjectName("inputFrame")
        input_layout = QVBoxLayout(input_frame)

        # Key input field (shared for Recovery/Password)
        self.key_input_label = QLabel("Recovery Key:")
        input_layout.addWidget(self.key_input_label)

        key_row = QHBoxLayout()
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText(
            "123456-234567-345678-456789-567890-678901-789012-890123"
        )
        self.key_input.setEnabled(self.pybde_available)
        # Dev: show key plaintext, Prod: mask recovery key
        if not self._dev_mode:
            self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_row.addWidget(self.key_input)

        self.show_key_btn = QPushButton("Show")
        self.show_key_btn.setFixedWidth(60)
        self.show_key_btn.setCheckable(True)
        self.show_key_btn.toggled.connect(self._toggle_key_visibility)
        key_row.addWidget(self.show_key_btn)

        input_layout.addLayout(key_row)

        # BEK file selection
        self.bek_layout = QHBoxLayout()
        self.bek_input = QLineEdit()
        self.bek_input.setPlaceholderText(".BEK file path")
        self.bek_input.setEnabled(False)
        self.bek_layout.addWidget(self.bek_input)

        self.bek_browse_btn = QPushButton("Browse...")
        self.bek_browse_btn.setEnabled(False)
        self.bek_browse_btn.clicked.connect(self._browse_bek_file)
        self.bek_layout.addWidget(self.bek_browse_btn)

        input_layout.addLayout(self.bek_layout)

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
        self.unlock_btn.setEnabled(self.pybde_available)
        self.unlock_btn.clicked.connect(self._on_unlock)
        self.unlock_btn.setMinimumWidth(100)
        button_layout.addWidget(self.unlock_btn)

        layout.addLayout(button_layout)

        # Connect signals
        self.radio_recovery.toggled.connect(self._on_key_type_changed)
        self.radio_password.toggled.connect(self._on_key_type_changed)
        self.radio_bek.toggled.connect(self._on_key_type_changed)
        self.radio_auto_decrypt.toggled.connect(self._on_key_type_changed)

    def _format_partition_info(self) -> str:
        """Format partition info"""
        info = self.partition_info
        size_gb = info.get('partition_size', 0) / (1024 ** 3)

        text = f"Partition #{info.get('partition_index', 0)}"
        if size_gb > 0:
            text += f" | Size: {size_gb:.1f} GB"
        if info.get('encryption_method'):
            text += f" | Encryption: {info['encryption_method']}"

        return text

    def _toggle_key_visibility(self, checked: bool):
        """Toggle key/password field visibility"""
        if checked:
            self.key_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_key_btn.setText("Hide")
        else:
            self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_key_btn.setText("Show")

    def _on_key_type_changed(self):
        """Update UI when key type changes"""
        # Reset show/hide toggle
        self.show_key_btn.setChecked(False)

        if self.radio_recovery.isChecked():
            self.key_input_label.setText("Recovery Key:")
            self.key_input.setPlaceholderText(
                "123456-234567-345678-456789-567890-678901-789012-890123"
            )
            self.key_input.setEnabled(True)
            # Dev: show plaintext, Prod: mask
            if self._dev_mode:
                self.key_input.setEchoMode(QLineEdit.EchoMode.Normal)
            else:
                self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_key_btn.setEnabled(True)
            self.bek_input.setEnabled(False)
            self.bek_browse_btn.setEnabled(False)

        elif self.radio_password.isChecked():
            self.key_input_label.setText("Password:")
            self.key_input.setPlaceholderText("Enter BitLocker password")
            self.key_input.setEnabled(True)
            self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_key_btn.setEnabled(True)
            self.bek_input.setEnabled(False)
            self.bek_browse_btn.setEnabled(False)

        elif self.radio_bek.isChecked():
            self.key_input_label.setText("BEK File:")
            self.key_input.setEnabled(False)
            self.key_input.clear()
            self.show_key_btn.setEnabled(False)
            self.bek_input.setEnabled(True)
            self.bek_browse_btn.setEnabled(True)

        elif self.radio_auto_decrypt.isChecked():
            self.key_input_label.setText("Auto-Decrypt:")
            self.key_input.setEnabled(False)
            self.key_input.clear()
            self.show_key_btn.setEnabled(False)
            self.key_input.setPlaceholderText("No key input required")
            self.bek_input.setEnabled(False)
            self.bek_browse_btn.setEnabled(False)
            self.unlock_btn.setText("Start Decrypt")
            self.unlock_btn.setEnabled(True)  # Auto-decrypt doesn't need pybde

        # Restore button text/state when not auto-decrypt
        if not self.radio_auto_decrypt.isChecked():
            self.unlock_btn.setText("Unlock")
            self.unlock_btn.setEnabled(self.pybde_available)

        self.error_label.hide()

    def _browse_bek_file(self):
        """BEK file selection dialog"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select BEK File",
            "",
            "BEK Files (*.bek *.BEK);;All Files (*)"
        )
        if file_path:
            self.bek_input.setText(file_path)

    def _show_error(self, message: str):
        """Display error message"""
        self.error_label.setText(f"❌ {message}")
        self.error_label.show()

    def _validate_input(self) -> bool:
        """Validate input"""
        if self.radio_recovery.isChecked():
            key = self.key_input.text().strip()
            if not key:
                self._show_error("Please enter a recovery key.")
                return False

            # Extract digits only
            digits = ''.join(c for c in key if c.isdigit())
            if len(digits) != 48:
                self._show_error(
                    f"Recovery key must be 48 digits. "
                    f"(Currently {len(digits)} digits)"
                )
                return False

            # Validate format: 8 groups of 6 digits separated by hyphens
            normalized = '-'.join(digits[i:i+6] for i in range(0, 48, 6))
            if not re.match(self._RECOVERY_KEY_PATTERN, normalized):
                self._show_error(
                    "Invalid recovery key format.\n"
                    "Expected: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
                )
                return False

        elif self.radio_password.isChecked():
            if not self.key_input.text():
                self._show_error("Please enter a password.")
                return False

        elif self.radio_bek.isChecked():
            bek_path = self.bek_input.text().strip()
            if not bek_path:
                self._show_error("Please select a BEK file.")
                return False
            if not os.path.exists(bek_path):
                self._show_error("BEK file does not exist.")
                return False

        elif self.radio_auto_decrypt.isChecked():
            # Check administrator privileges
            try:
                from utils.bitlocker import check_admin_privileges
                if not check_admin_privileges():
                    self._show_error(
                        "Administrator privileges required.\n"
                        "Please run the collector as administrator."
                    )
                    return False
            except ImportError:
                pass  # Proceed if module not available

        return True

    def _on_unlock(self):
        """Unlock button clicked"""
        if not self._validate_input():
            return

        self.result.success = True
        self.result.skip = False

        if self.radio_recovery.isChecked():
            self.result.key_type = "recovery_password"
            # Convert recovery key to standard format
            key = self.key_input.text().strip()
            digits = ''.join(c for c in key if c.isdigit())
            groups = [digits[i:i+6] for i in range(0, 48, 6)]
            self.result.key_value = '-'.join(groups)

        elif self.radio_password.isChecked():
            self.result.key_type = "password"
            self.result.key_value = self.key_input.text()

        elif self.radio_bek.isChecked():
            self.result.key_type = "bek_file"
            self.result.bek_path = self.bek_input.text().strip()

        elif self.radio_auto_decrypt.isChecked():
            # Confirmation dialog
            reply = QMessageBox.warning(
                self,
                "BitLocker Auto-Decrypt Confirmation",
                "Warning: The system's BitLocker encryption will be disabled.\n\n"
                "- May take several minutes to hours depending on disk size.\n"
                "- Will automatically re-encrypt after collection completes.\n"
                "- Do not shut down the system during this operation.\n\n"
                "Do you want to continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )

            if reply != QMessageBox.StandardButton.Yes:
                return

            self.result.key_type = "auto_decrypt"
            self.result.auto_decrypt = True

        self.accept()

    def _on_skip(self):
        """Skip button clicked"""
        # Confirmation dialog
        reply = QMessageBox.question(
            self,
            "Skip BitLocker",
            "Skipping BitLocker decryption will collect data in encrypted state.\n"
            "Some artifacts may not be extractable.\n\n"
            "Do you want to continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.result.success = False
            self.result.skip = True
            self.accept()

    def get_result(self) -> BitLockerDialogResult:
        """Return result"""
        return self.result

    def _get_stylesheet(self) -> str:
        """Stylesheet - platform unified theme"""
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
            #keyGroup {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 6px;
                padding: 8px;
                color: {COLORS['text_primary']};
                font-size: 11px;
            }}
            QRadioButton {{
                color: {COLORS['text_primary']};
                background-color: transparent;
                font-size: 11px;
                padding: 4px 0;
                spacing: 8px;
            }}
            QRadioButton::indicator {{
                width: 16px;
                height: 16px;
                border: 2px solid {COLORS['border_default']};
                border-radius: 9px;
                background-color: {COLORS['bg_tertiary']};
            }}
            QRadioButton::indicator:checked {{
                background-color: {COLORS['brand_primary']};
                border-color: {COLORS['brand_primary']};
            }}
            QRadioButton::indicator:hover {{
                border-color: {COLORS['brand_accent']};
            }}
            QRadioButton:disabled {{
                color: {COLORS['text_tertiary']};
            }}
            QRadioButton::indicator:disabled {{
                border-color: {COLORS['border_subtle']};
                background-color: {COLORS['bg_secondary']};
            }}
            #keyDesc {{
                color: {COLORS['text_secondary']};
                font-size: 9px;
                margin-left: 20px;
                margin-bottom: 4px;
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
            QLineEdit::placeholder {{
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


def show_bitlocker_dialog(
    partition_info: dict = None,
    pybde_available: bool = True,
    config: dict = None,
    parent=None
) -> BitLockerDialogResult:
    """
    Display BitLocker dialog and return result.

    Args:
        partition_info: Partition information
        pybde_available: Whether pybde is installed
        config: Application config (for dev_mode flag)
        parent: Parent widget

    Returns:
        BitLockerDialogResult
    """
    dialog = BitLockerDialog(
        partition_info=partition_info,
        pybde_available=pybde_available,
        config=config,
        parent=parent
    )
    result_code = dialog.exec()

    if result_code == QDialog.DialogCode.Accepted:
        return dialog.get_result()

    # If cancelled
    return BitLockerDialogResult(success=False, skip=False)


if __name__ == "__main__":
    # For testing
    from PyQt6.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)

    # Test partition info
    test_info = {
        'partition_index': 0,
        'partition_offset': 1048576,
        'partition_size': 256 * 1024 * 1024 * 1024,  # 256GB
        'encryption_method': 'AES-256-XTS'
    }

    show_bitlocker_dialog(
        partition_info=test_info,
        pybde_available=True,
        config={'dev_mode': True}
    )
