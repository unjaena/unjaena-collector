# -*- coding: utf-8 -*-
"""
iOS Encrypted Backup Password Dialog

Simple password input dialog for encrypted iOS backups.
No background verification - key derivation key derivation is performed once
in the CollectionWorker thread during collection.

Security:
    - Password used client-side only (zero-knowledge model)
    - Password cleared from dialog after acceptance
    - Actual verification happens in collection thread (single key derivation)
"""
from dataclasses import dataclass
from typing import Optional

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QMessageBox
)
from PyQt6.QtCore import Qt

from gui.styles import COLORS


@dataclass
class iOSPasswordDialogResult:
    """iOS password dialog result"""
    success: bool = False
    password: str = ""
    skip: bool = False          # Exclude encrypted backup from collection

    def clear_sensitive(self):
        """Clear password from memory (release reference for GC)"""
        self.password = ""


class iOSPasswordDialog(QDialog):
    """iOS encrypted backup password input dialog"""

    def __init__(self, backup_info: dict = None, library_available: bool = True, parent=None):
        """
        Args:
            backup_info: Backup information dict
                - device_name, ios_version, backup_date, size_mb, path
                - is_usb_device: True for USB-connected devices (optional password)
            library_available: Whether iphone_backup_decrypt is installed
            parent: Parent widget
        """
        super().__init__(parent)
        self.backup_info = backup_info or {}
        self.library_available = library_available
        self.is_usb_device = self.backup_info.get('is_usb_device', False)
        self.result = iOSPasswordDialogResult()
        self.setup_ui()

    def setup_ui(self):
        """Initialize UI"""
        if self.is_usb_device:
            title = "iOS Device Backup Password"
            header_text = "iOS Device Backup Password"
            info_text = (
                "If this device has backup encryption enabled,\n"
                "enter the backup password to decrypt collected artifacts.\n"
                "If no password is set, click 'No Password' to continue.\n"
                "The password is used locally only and is never transmitted."
            )
        else:
            title = "Encrypted iOS Backup Detected"
            header_text = "Encrypted iOS Backup Detected"
            info_text = (
                "This iOS backup is encrypted with a password.\n"
                "Enter the backup password to decrypt and collect artifacts.\n"
                "The password is used locally only and is never transmitted."
            )

        self.setWindowTitle(title)
        self.setMinimumSize(480, 360)
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 16, 16, 16)

        # Header
        header = QLabel(header_text)
        header.setObjectName("header")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Info banner
        info_frame = QFrame()
        info_frame.setObjectName("infoFrame")
        info_layout = QVBoxLayout(info_frame)
        info_label = QLabel(info_text)
        info_label.setObjectName("infoText")
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)

        # Backup info display
        if self.backup_info:
            backup_text = self._format_backup_info()
            backup_label = QLabel(backup_text)
            backup_label.setObjectName("backupInfo")
            info_layout.addWidget(backup_label)

        layout.addWidget(info_frame)

        # Library not installed warning
        if not self.library_available:
            warning_frame = QFrame()
            warning_frame.setObjectName("warningFrame")
            warning_layout = QVBoxLayout(warning_frame)
            warning_label = QLabel(
                "Warning: iphone_backup_decrypt is not installed.\n"
                "Install with: pip install iphone_backup_decrypt"
            )
            warning_label.setObjectName("warningText")
            warning_label.setWordWrap(True)
            warning_layout.addWidget(warning_label)
            layout.addWidget(warning_frame)

        # Password input area
        input_frame = QFrame()
        input_frame.setObjectName("inputFrame")
        input_layout = QVBoxLayout(input_frame)

        self.password_label = QLabel("Backup Password:")
        input_layout.addWidget(self.password_label)

        # Password field with show/hide toggle
        pw_row = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter iOS backup password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setEnabled(self.library_available)
        self.password_input.returnPressed.connect(self._on_ok)
        pw_row.addWidget(self.password_input)

        self.show_pw_btn = QPushButton("Show")
        self.show_pw_btn.setFixedWidth(60)
        self.show_pw_btn.setCheckable(True)
        self.show_pw_btn.toggled.connect(self._toggle_password_visibility)
        pw_row.addWidget(self.show_pw_btn)

        input_layout.addLayout(pw_row)

        # Note about verification timing
        note_text = (
            "Password will be validated before backup starts."
            if self.is_usb_device else
            "Password will be verified when collection starts (1-2 minutes)."
        )
        note_label = QLabel(note_text)
        note_label.setObjectName("noteLabel")
        input_layout.addWidget(note_label)

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

        skip_text = "No Password" if self.is_usb_device else "Skip (Exclude This Backup)"
        self.skip_btn = QPushButton(skip_text)
        self.skip_btn.clicked.connect(self._on_skip)
        self.skip_btn.setMinimumWidth(180)
        button_layout.addWidget(self.skip_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setMinimumWidth(80)
        button_layout.addWidget(self.cancel_btn)

        self.ok_btn = QPushButton("OK")
        self.ok_btn.setObjectName("unlockButton")
        self.ok_btn.setEnabled(self.library_available)
        self.ok_btn.clicked.connect(self._on_ok)
        self.ok_btn.setMinimumWidth(100)
        button_layout.addWidget(self.ok_btn)

        layout.addLayout(button_layout)

    def _format_backup_info(self) -> str:
        """Format backup info for display"""
        info = self.backup_info
        parts = []

        device_name = info.get('device_name', '')
        if device_name:
            parts.append(f"Device: {device_name}")

        ios_version = info.get('ios_version', '')
        if ios_version:
            parts.append(f"iOS {ios_version}")

        size_mb = info.get('size_mb', 0)
        if size_mb:
            if size_mb > 1024:
                parts.append(f"Size: {size_mb / 1024:.1f} GB")
            else:
                parts.append(f"Size: {size_mb:.0f} MB")

        backup_date = info.get('backup_date', '')
        if backup_date:
            parts.append(f"Date: {backup_date}")

        return " | ".join(parts) if parts else "Unknown backup"

    def _toggle_password_visibility(self, checked: bool):
        """Toggle password field visibility"""
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_pw_btn.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_pw_btn.setText("Show")

    def _on_ok(self):
        """OK button clicked"""
        password = self.password_input.text()
        if not password:
            self.error_label.setText("Please enter a password.")
            self.error_label.show()
            return

        self.error_label.hide()
        self.result.success = True
        self.result.password = password
        self.result.skip = False

        # Clear password from UI immediately
        self.password_input.clear()
        self.accept()

    def _on_skip(self):
        """Skip button clicked"""
        if self.is_usb_device:
            # USB device: no password = auto-encrypt with forensic password
            self.result.success = False
            self.result.skip = True
            self.accept()
        else:
            reply = QMessageBox.question(
                self,
                "Skip Encrypted Backup",
                "Skipping this encrypted backup means its artifacts\n"
                "will not be collected.\n\n"
                "Other non-encrypted devices will still be collected.\n\n"
                "Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.result.success = False
                self.result.skip = True
                self.accept()

    def get_result(self) -> iOSPasswordDialogResult:
        """Return result"""
        return self.result

    def _get_stylesheet(self) -> str:
        """Stylesheet - matches platform theme"""
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
            #backupInfo {{
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
            QLineEdit::placeholder {{
                color: {COLORS['text_tertiary']};
            }}
            QLabel {{
                color: {COLORS['text_primary']};
                font-size: 11px;
            }}
            #noteLabel {{
                color: {COLORS['text_secondary']};
                font-size: 9px;
                font-style: italic;
                padding: 2px 0;
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


def show_ios_password_dialog(
    backup_info: dict = None,
    library_available: bool = True,
    parent=None
) -> iOSPasswordDialogResult:
    """
    Display iOS password dialog and return result.

    Args:
        backup_info: Backup information dict
        library_available: Whether iphone_backup_decrypt is installed
        parent: Parent widget

    Returns:
        iOSPasswordDialogResult
    """
    dialog = iOSPasswordDialog(
        backup_info=backup_info,
        library_available=library_available,
        parent=parent
    )
    result_code = dialog.exec()

    if result_code == QDialog.DialogCode.Accepted:
        return dialog.get_result()

    # If cancelled
    return iOSPasswordDialogResult(success=False, skip=False)


class iOSBackupPasswordDialog(QDialog):
    """
    iOS USB backup password dialog.

    Shown when a USB-connected device has backup encryption enabled with
    an unknown password. Supports retry loop (error_msg from previous attempt).
    """

    def __init__(self, error_msg: str = "", parent=None):
        super().__init__(parent)
        self.result = iOSPasswordDialogResult()
        self._error_msg = error_msg
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("iOS Backup Password Required")
        self.setMinimumSize(480, 320)
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 16, 16, 16)

        # Header
        header = QLabel("iOS Backup Password Required")
        header.setObjectName("header")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Info banner
        info_frame = QFrame()
        info_frame.setObjectName("infoFrame")
        info_layout = QVBoxLayout(info_frame)
        info_label = QLabel(
            "This device has backup encryption enabled.\n"
            "Enter your backup password to proceed with collection.\n"
            "The password is used locally only and is never transmitted."
        )
        info_label.setObjectName("infoText")
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)
        layout.addWidget(info_frame)

        # Error message (shown on retry)
        self.error_label = QLabel("")
        self.error_label.setObjectName("errorLabel")
        self.error_label.setWordWrap(True)
        if self._error_msg:
            self.error_label.setText(self._error_msg)
            self.error_label.show()
        else:
            self.error_label.hide()
        layout.addWidget(self.error_label)

        # Password input area
        input_frame = QFrame()
        input_frame.setObjectName("inputFrame")
        input_layout = QVBoxLayout(input_frame)

        input_layout.addWidget(QLabel("Backup Password:"))

        pw_row = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter iOS backup password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.returnPressed.connect(self._on_ok)
        pw_row.addWidget(self.password_input)

        self.show_pw_btn = QPushButton("Show")
        self.show_pw_btn.setFixedWidth(60)
        self.show_pw_btn.setCheckable(True)
        self.show_pw_btn.toggled.connect(self._toggle_password_visibility)
        pw_row.addWidget(self.show_pw_btn)

        input_layout.addLayout(pw_row)
        layout.addWidget(input_frame)

        # Buttons: I don't know | Cancel | OK
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.idk_btn = QPushButton("I don't know")
        self.idk_btn.clicked.connect(self._on_idk)
        self.idk_btn.setMinimumWidth(120)
        button_layout.addWidget(self.idk_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setMinimumWidth(80)
        button_layout.addWidget(self.cancel_btn)

        self.ok_btn = QPushButton("OK")
        self.ok_btn.setObjectName("unlockButton")
        self.ok_btn.clicked.connect(self._on_ok)
        self.ok_btn.setMinimumWidth(100)
        button_layout.addWidget(self.ok_btn)

        layout.addLayout(button_layout)

        # Focus password input
        self.password_input.setFocus()

    def _toggle_password_visibility(self, checked: bool):
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_pw_btn.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_pw_btn.setText("Show")

    def _on_ok(self):
        password = self.password_input.text()
        if not password:
            self.error_label.setText("Please enter a password.")
            self.error_label.show()
            return

        self.error_label.hide()
        self.result.success = True
        self.result.password = password
        self.password_input.clear()
        self.accept()

    def _on_idk(self):
        """Show reset instructions and abort."""
        QMessageBox.information(
            self,
            "How to Reset Backup Password",
            "To reset the iOS backup password:\n\n"
            "  Settings > General > Transfer or Reset iPhone\n"
            "  > Reset > Reset All Settings\n\n"
            "This preserves all data — only settings are reset.\n"
            "After reset, run collection again."
        )
        self.result.success = False
        self.result.skip = True
        self.reject()

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
            #unlockButton {{
                background-color: {COLORS['brand_primary']};
                border: none;
                color: {COLORS['bg_primary']};
                font-weight: bold;
            }}
            #unlockButton:hover {{
                background-color: {COLORS['brand_accent']};
            }}
        """


class iOSEncryptionSetupDialog(QDialog):
    """
    Dialog for setting a temporary encryption password on an iOS device.

    Shown when backup encryption is OFF. The user enters a temporary password
    to enable encryption for complete forensic data. After collection,
    encryption is restored to OFF using this same password.
    If a crash occurs, the user knows the password and can manage it themselves.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.result = iOSPasswordDialogResult()
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("iOS Backup Encryption Setup")
        self.setMinimumSize(500, 380)
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 16, 16, 16)

        # Header
        header = QLabel("Backup Encryption Setup")
        header.setObjectName("header")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Info banner
        info_frame = QFrame()
        info_frame.setObjectName("infoFrame")
        info_layout = QVBoxLayout(info_frame)
        info_label = QLabel(
            "Encrypted backups contain more forensic data\n"
            "(HealthKit, WiFi passwords, saved accounts, etc.)\n\n"
            "Enter a temporary password to enable backup encryption.\n"
            "This password will be used to restore the device after collection.\n"
            "The password is used locally only and is never transmitted."
        )
        info_label.setObjectName("infoText")
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)
        layout.addWidget(info_frame)

        # Password input area
        input_frame = QFrame()
        input_frame.setObjectName("inputFrame")
        input_layout = QVBoxLayout(input_frame)

        input_layout.addWidget(QLabel("Temporary Encryption Password:"))

        pw_row = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter a temporary password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.returnPressed.connect(self._on_ok)
        pw_row.addWidget(self.password_input)

        self.show_pw_btn = QPushButton("Show")
        self.show_pw_btn.setFixedWidth(60)
        self.show_pw_btn.setCheckable(True)
        self.show_pw_btn.toggled.connect(self._toggle_password_visibility)
        pw_row.addWidget(self.show_pw_btn)

        input_layout.addLayout(pw_row)

        # Note
        note_label = QLabel(
            "Remember this password — if the collector crashes during collection,\n"
            "you can use it in iTunes/Finder to manage backup encryption."
        )
        note_label.setObjectName("noteLabel")
        note_label.setWordWrap(True)
        input_layout.addWidget(note_label)

        # Error label
        self.error_label = QLabel("")
        self.error_label.setObjectName("errorLabel")
        self.error_label.hide()
        input_layout.addWidget(self.error_label)

        layout.addWidget(input_frame)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.skip_btn = QPushButton("Skip (Collect Without Encryption)")
        self.skip_btn.clicked.connect(self._on_skip)
        self.skip_btn.setMinimumWidth(220)
        button_layout.addWidget(self.skip_btn)

        self.ok_btn = QPushButton("Enable Encryption")
        self.ok_btn.setObjectName("unlockButton")
        self.ok_btn.clicked.connect(self._on_ok)
        self.ok_btn.setMinimumWidth(140)
        button_layout.addWidget(self.ok_btn)

        layout.addLayout(button_layout)
        self.password_input.setFocus()

    def _toggle_password_visibility(self, checked: bool):
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_pw_btn.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_pw_btn.setText("Show")

    def _on_ok(self):
        password = self.password_input.text()
        if not password:
            self.error_label.setText("Please enter a password.")
            self.error_label.show()
            return

        self.error_label.hide()
        self.result.success = True
        self.result.password = password
        self.password_input.clear()
        self.accept()

    def _on_skip(self):
        self.result.success = False
        self.result.skip = True
        self.accept()

    def _get_stylesheet(self) -> str:
        return f"""
            QDialog {{
                background-color: {COLORS['bg_primary']};
            }}
            #header {{
                font-size: 16px;
                font-weight: bold;
                color: {COLORS['info']};
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
            QLineEdit::placeholder {{
                color: {COLORS['text_tertiary']};
            }}
            QLabel {{
                color: {COLORS['text_primary']};
                font-size: 11px;
            }}
            #noteLabel {{
                color: {COLORS['warning']};
                font-size: 9px;
                font-style: italic;
                padding: 2px 0;
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
            #unlockButton {{
                background-color: {COLORS['brand_primary']};
                border: none;
                color: {COLORS['bg_primary']};
                font-weight: bold;
            }}
            #unlockButton:hover {{
                background-color: {COLORS['brand_accent']};
            }}
        """


def show_ios_encryption_setup_dialog(parent=None) -> iOSPasswordDialogResult:
    """Display iOS encryption setup dialog for devices without backup encryption."""
    dialog = iOSEncryptionSetupDialog(parent=parent)
    result_code = dialog.exec()
    if result_code == QDialog.DialogCode.Accepted:
        return dialog.result
    return iOSPasswordDialogResult(success=False, skip=False)


def show_ios_backup_password_dialog(
    error_msg: str = "",
    parent=None
) -> iOSPasswordDialogResult:
    """
    Display iOS USB backup password dialog.

    Called from GUI thread when the collector's password callback fires.

    Args:
        error_msg: Error hint from previous attempt (e.g. "Incorrect password")
        parent: Parent widget

    Returns:
        iOSPasswordDialogResult (success=True + password, or success=False)
    """
    dialog = iOSBackupPasswordDialog(error_msg=error_msg, parent=parent)
    result_code = dialog.exec()

    if result_code == QDialog.DialogCode.Accepted:
        return dialog.result

    return iOSPasswordDialogResult(success=False, skip=False)
