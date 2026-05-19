# -*- coding: utf-8 -*-
"""
Android Device Info Dialog

Displayed before collection starts to inform the user of:
- Device specifications (model, Android version, SDK, security patch, root status)
- Available collection phases for the connected device
- Items that cannot be collected and why
- Legal notice
"""

from dataclasses import dataclass

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QScrollArea, QWidget
)
from PyQt6.QtCore import Qt

from gui.styles import COLORS
from collectors.android_collector import _load_advanced_plugin


# =============================================================================
# Result Dataclass
# =============================================================================

@dataclass
class AndroidInfoDialogResult:
    """Whether to proceed with collection."""
    proceed: bool = False


# =============================================================================
# Dialog
# =============================================================================

class AndroidDeviceInfoDialog(QDialog):
    """
    Pre-collection information dialog for Android devices.

    Displays:
      - Device specs (model, version, SDK, patch, root status)
      - Available / unavailable collection phases
      - Legal notice
    """

    def __init__(self, device_info: dict, parent=None):
        super().__init__(parent)
        self.device_info = device_info
        self._result = AndroidInfoDialogResult()
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI Build
    # ------------------------------------------------------------------

    def _setup_ui(self):
        self.setWindowTitle("Android Device — Collection Info")
        self.setMinimumWidth(500)
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(16, 16, 16, 16)

        header = QLabel("📱 Android Device — Collection Information")
        header.setObjectName("headerLabel")
        root.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(8)
        content_layout.setContentsMargins(0, 0, 4, 0)

        content_layout.addWidget(self._build_device_spec_frame())
        content_layout.addWidget(self._build_collection_methods_frame())
        content_layout.addWidget(self._build_legal_frame())
        content_layout.addStretch()

        scroll.setWidget(content)
        root.addWidget(scroll)
        root.addWidget(self._build_button_row())

    def _build_device_spec_frame(self) -> QFrame:
        """Device specification panel."""
        frame = QFrame()
        frame.setObjectName("infoFrame")
        layout = QVBoxLayout(frame)
        layout.setSpacing(4)
        layout.setContentsMargins(10, 8, 10, 8)

        title = QLabel("Device Information")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        d = self.device_info
        rooted = d.get('rooted', False)
        sdk = d.get('sdk_version', 0)
        patch = d.get('security_patch', '') or 'Unknown'
        storage = d.get('storage_available', 0)
        storage_str = f"{storage / (1024**3):.1f} GB" if storage else 'Unknown'

        rows = [
            ("Model",          f"{d.get('manufacturer', '')} {d.get('model', 'Unknown')}".strip()),
            ("Android",        f"Android {d.get('android_version', '?')} (SDK {sdk})"),
            ("Security Patch", patch),
            ("Root",           "Rooted" if rooted else "Not rooted"),
            ("USB Debugging",  "Enabled" if d.get('usb_debugging', False) else "Disabled"),
            ("Free Storage",   storage_str),
        ]

        for key, val in rows:
            row = QHBoxLayout()
            row.setSpacing(8)
            k_lbl = QLabel(key)
            k_lbl.setObjectName("rowKey")
            k_lbl.setFixedWidth(90)
            if key == "Root":
                v_lbl = QLabel(val)
                v_lbl.setObjectName("rowValGood" if rooted else "rowValWarn")
            else:
                v_lbl = QLabel(val)
                v_lbl.setObjectName("rowVal")
            row.addWidget(k_lbl)
            row.addWidget(v_lbl)
            row.addStretch()
            layout.addLayout(row)

        return frame

    def _build_collection_methods_frame(self) -> QFrame:
        """Available collection phases panel."""
        frame = QFrame()
        frame.setObjectName("infoFrame")
        layout = QVBoxLayout(frame)
        layout.setSpacing(4)
        layout.setContentsMargins(10, 8, 10, 8)

        title = QLabel("Collection Methods & Scope")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        d = self.device_info
        sdk = d.get('sdk_version', 0)
        patch = d.get('security_patch', '') or ''
        rooted = d.get('rooted', False)

        # (status, name, description)
        phases = [
            (
                "available",
                "Phase 1 — External Storage (sdcard)",
                "Media files and messenger app external data (KakaoTalk, WhatsApp, Telegram, etc.).\n"
                "No root required. App internal databases are not included."
            ),
            (
                "partial",
                "Phase 2 — run-as (debuggable apps only)",
                "Accesses internal databases if the app is built with debuggable=true.\n"
                "Most production apps disable this — expect high failure rate."
            ),
            (
                "available" if _load_advanced_plugin() else "unavailable",
                "Phase 3a — Advanced Access (Pro Plugin)",
                "Requires unjaena-collector-pro plugin (licensed agencies only).\n"
                "Provides additional extraction methods for authorized forensic use."
            ),
            (
                "unavailable",
                "Phase 3b — Advanced Kernel Access (Pro Plugin)",
                "Requires unjaena-collector-pro plugin. Not available in this build."
            ),
            (
                "partial",
                "Phase 3c — /proc/pid/fd Memory Access",
                "Attempts collection through open file handles while the app is running.\n"
                "Android 10+ permission restrictions usually result in empty output."
            ),
            (
                "partial",
                "Phase 3d — Content Provider Enumeration",
                "Queries data through exported Content Providers.\n"
                "Most apps do not expose providers — limited collection scope."
            ),
            (
                "available",
                "Phase 3e — ADB Backup",
                "Extracts data from apps with allowBackup=true as an .ab archive.\n"
                "Applicable to Telegram, KakaoTalk, WhatsApp, and similar apps."
            ),
            (
                "available" if rooted else "unavailable",
                "Root Collection — Direct App Database Access",
                f"/data/data/ full access — collects DBs, settings, and caches from all apps.\n"
                f"This device: {'Root confirmed' if rooted else 'No root — not available'}."
            ),
        ]

        status_icons = {
            "available":   ("✔", COLORS['success']),
            "partial":     ("△", COLORS['warning']),
            "unavailable": ("✘", COLORS['error']),
        }

        for status, name, desc in phases:
            icon, color = status_icons[status]
            row_w = QWidget()
            row_l = QVBoxLayout(row_w)
            row_l.setSpacing(1)
            row_l.setContentsMargins(0, 3, 0, 3)

            name_lbl = QLabel(f"<span style='color:{color};'>{icon}</span>  {name}")
            name_lbl.setObjectName("phaseTitle")
            desc_lbl = QLabel(desc)
            desc_lbl.setObjectName("phaseDesc")
            desc_lbl.setWordWrap(True)

            row_l.addWidget(name_lbl)
            row_l.addWidget(desc_lbl)
            layout.addWidget(row_w)

        if not rooted:
            tip = QFrame()
            tip.setObjectName("warningFrame")
            tip_l = QVBoxLayout(tip)
            tip_l.setContentsMargins(8, 6, 8, 6)
            tip_l.addWidget(QLabel(
                "Tip: Full collection of app internal databases (chat history, account data, etc.)\n"
                "requires TWRP + Magisk root or professional hardware extraction."
            ))
            layout.addWidget(tip)

        return frame

    def _build_legal_frame(self) -> QFrame:
        """Legal notice panel."""
        frame = QFrame()
        frame.setObjectName("warningFrame")
        layout = QVBoxLayout(frame)
        layout.setSpacing(4)
        layout.setContentsMargins(10, 8, 10, 8)

        title = QLabel("⚖ Legal Notice")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        notices = [
            "This tool must only be used for lawful digital forensics purposes.",
            "You must have the device owner's consent or a valid search warrant.",
            "Advanced access methods (Phase 3a) require the pro plugin for licensed agencies.",
            "Collected data must be handled in accordance with Chain of Custody procedures.",
            "Do not modify device settings or data during collection.",
        ]

        for notice in notices:
            lbl = QLabel(f"• {notice}")
            lbl.setObjectName("noticeText")
            lbl.setWordWrap(True)
            layout.addWidget(lbl)

        return frame

    def _build_button_row(self) -> QWidget:
        w = QWidget()
        layout = QHBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setFixedWidth(90)
        cancel_btn.clicked.connect(self._on_cancel)
        layout.addWidget(cancel_btn)

        proceed_btn = QPushButton("Proceed")
        proceed_btn.setObjectName("primaryButton")
        proceed_btn.setFixedWidth(100)
        proceed_btn.clicked.connect(self._on_proceed)
        layout.addWidget(proceed_btn)

        return w

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_proceed(self):
        self._result = AndroidInfoDialogResult(proceed=True)
        self.accept()

    def _on_cancel(self):
        self._result = AndroidInfoDialogResult(proceed=False)
        self.reject()

    def get_result(self) -> AndroidInfoDialogResult:
        return self._result

    # ------------------------------------------------------------------
    # Stylesheet
    # ------------------------------------------------------------------

    def _get_stylesheet(self) -> str:
        C = COLORS
        return f"""
        QDialog {{
            background-color: {C['bg_primary']};
        }}
        QScrollArea, QWidget {{
            background-color: transparent;
        }}
        QLabel#headerLabel {{
            font-size: 13px;
            font-weight: 600;
            color: {C['text_primary']};
            padding-bottom: 4px;
        }}
        QFrame#infoFrame {{
            background-color: {C['bg_secondary']};
            border: 1px solid {C['border_subtle']};
            border-radius: 6px;
        }}
        QFrame#warningFrame {{
            background-color: {C['warning_bg']};
            border: 1px solid {C['warning']};
            border-radius: 6px;
        }}
        QLabel#sectionTitle {{
            font-size: 11px;
            font-weight: 600;
            color: {C['brand_primary']};
            padding-bottom: 2px;
        }}
        QLabel#rowKey {{
            font-size: 10px;
            color: {C['text_secondary']};
        }}
        QLabel#rowVal {{
            font-size: 10px;
            color: {C['text_primary']};
        }}
        QLabel#rowValGood {{
            font-size: 10px;
            color: {C['success']};
            font-weight: 600;
        }}
        QLabel#rowValWarn {{
            font-size: 10px;
            color: {C['warning']};
        }}
        QLabel#phaseTitle {{
            font-size: 10px;
            font-weight: 600;
            color: {C['text_primary']};
        }}
        QLabel#phaseDesc {{
            font-size: 9px;
            color: {C['text_secondary']};
            padding-left: 18px;
        }}
        QLabel#noticeText {{
            font-size: 9px;
            color: {C['text_secondary']};
        }}
        QPushButton {{
            background-color: {C['bg_tertiary']};
            border: 1px solid {C['border_subtle']};
            border-radius: 4px;
            padding: 5px 12px;
            color: {C['text_primary']};
            font-size: 11px;
        }}
        QPushButton:hover {{
            background-color: {C['bg_hover']};
        }}
        QPushButton#primaryButton {{
            background-color: {C['brand_primary']};
            border: none;
            color: {C['bg_primary']};
            font-weight: 600;
        }}
        QPushButton#primaryButton:hover {{
            background-color: {C['brand_accent']};
        }}
        """


# =============================================================================
# Public API
# =============================================================================

def show_android_info_dialog(
    device_info: dict,
    parent=None
) -> AndroidInfoDialogResult:
    """
    Show the Android pre-collection info dialog and return the result.

    Args:
        device_info: Dict with DeviceInfo fields
                     (model, manufacturer, android_version, sdk_version,
                      rooted, security_patch, usb_debugging, storage_available)
        parent: Parent QWidget

    Returns:
        AndroidInfoDialogResult — proceed=True means the user confirmed collection.
    """
    dialog = AndroidDeviceInfoDialog(device_info=device_info, parent=parent)
    if dialog.exec() == QDialog.DialogCode.Accepted:
        return dialog.get_result()
    return AndroidInfoDialogResult(proceed=False)
