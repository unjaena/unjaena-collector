from __future__ import annotations

import os
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Any

try:
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QDialog,
        QDialogButtonBox,
        QFileDialog,
        QFrame,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QScrollArea,
        QSplitter,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ModuleNotFoundError:
    QApplication = None
    Qt = None
    QMainWindow = object

from .client import ServiceClient
from . import __version__
from .models import CollectionProfile, ProfileTarget
from .runner import ProfileRunner
from .privileges import privilege_status, relaunch_elevated
from .updater import UpdateInfo, check_for_update, open_update
from .device_discovery import DeviceInfo, discover_devices
from .source_formats import (
    SOURCE_FILE_FILTER,
    SOURCE_TYPE_OPTIONS,
    classify_source_path,
    format_file_size,
)

DEFAULT_SERVER_URL = os.environ.get("UNJAENA_SERVER_URL", "https://app.unjaena.com")

COLORS = {
    "bg_primary": "#0a0f14",
    "bg_secondary": "#101820",
    "bg_tertiary": "#15202b",
    "bg_hover": "#1d2a36",
    "bg_active": "#263545",
    "text_primary": "#eef3f8",
    "text_secondary": "#a8b3bd",
    "text_tertiary": "#77838e",
    "brand_primary": "#c99a6b",
    "brand_secondary": "#9fb7c8",
    "brand_accent": "#e0b987",
    "success": "#45c46b",
    "warning": "#d9a441",
    "error": "#ff665c",
    "info": "#72b7ff",
    "border_subtle": "#253241",
    "border_default": "#34475a",
}

SOURCE_UPLOAD_KINDS = {
    "source_file",
    "image_file",
    "forensic_image",
    "disk_image",
    "bundle",
    "manual_file",
    "raw_upload",
}


def _safe_text(value: Any, limit: int = 160) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _stylesheet() -> str:
    return f"""
    * {{ font-family: 'Segoe UI', 'Arial', sans-serif; }}
    QMainWindow, QWidget {{ background-color: {COLORS['bg_primary']}; color: {COLORS['text_primary']}; }}
    QFrame#header {{ background-color: {COLORS['bg_secondary']}; border: 1px solid {COLORS['border_subtle']}; border-radius: 6px; }}
    QGroupBox {{ background-color: {COLORS['bg_secondary']}; border: 1px solid {COLORS['border_subtle']}; border-radius: 6px; margin-top: 10px; padding: 9px; padding-top: 18px; }}
    QGroupBox::title {{ subcontrol-origin: margin; subcontrol-position: top left; left: 10px; padding: 0 6px; color: {COLORS['brand_primary']}; background-color: {COLORS['bg_secondary']}; font-weight: 600; }}
    QLabel {{ color: {COLORS['text_primary']}; background: transparent; }}
    QLabel#muted {{ color: {COLORS['text_tertiary']}; font-size: 11px; }}
    QLabel#statusOk {{ color: {COLORS['success']}; font-weight: 600; }}
    QLabel#statusWarn {{ color: {COLORS['warning']}; font-weight: 600; }}
    QLabel#statusError {{ color: {COLORS['error']}; font-weight: 600; }}
    QLineEdit, QTextEdit, QListWidget, QComboBox {{ background-color: {COLORS['bg_tertiary']}; border: 1px solid {COLORS['border_subtle']}; border-radius: 5px; color: {COLORS['text_primary']}; padding: 7px; selection-background-color: {COLORS['bg_active']}; }}
    QLineEdit:focus, QTextEdit:focus, QListWidget:focus, QComboBox:focus {{ border-color: {COLORS['brand_primary']}; }}
    QPushButton {{ background-color: {COLORS['bg_tertiary']}; border: 1px solid {COLORS['border_subtle']}; border-radius: 5px; padding: 7px 12px; color: {COLORS['text_primary']}; font-weight: 600; }}
    QPushButton:hover {{ background-color: {COLORS['bg_hover']}; border-color: {COLORS['border_default']}; }}
    QPushButton:disabled {{ color: {COLORS['text_tertiary']}; border-color: {COLORS['border_subtle']}; background-color: {COLORS['bg_tertiary']}; }}
    QPushButton#primary {{ background-color: {COLORS['brand_primary']}; color: {COLORS['bg_primary']}; border: none; }}
    QPushButton#primary:hover {{ background-color: {COLORS['brand_accent']}; }}
    QCheckBox {{ spacing: 8px; color: {COLORS['text_primary']}; }}
    QCheckBox:disabled {{ color: {COLORS['text_tertiary']}; }}
    QTabWidget::pane {{ border: 1px solid {COLORS['border_subtle']}; border-radius: 6px; background-color: {COLORS['bg_tertiary']}; }}
    QTabBar::tab {{ background-color: {COLORS['bg_secondary']}; color: {COLORS['text_secondary']}; border: 1px solid {COLORS['border_subtle']}; padding: 6px 12px; margin-right: 2px; border-top-left-radius: 5px; border-top-right-radius: 5px; }}
    QTabBar::tab:selected {{ color: {COLORS['text_primary']}; background-color: {COLORS['bg_tertiary']}; border-bottom-color: {COLORS['bg_tertiary']}; }}
    QProgressBar {{ background-color: {COLORS['bg_tertiary']}; border: 1px solid {COLORS['border_subtle']}; border-radius: 5px; height: 14px; text-align: center; }}
    QProgressBar::chunk {{ background-color: {COLORS['brand_primary']}; border-radius: 4px; }}
    QScrollArea {{ border: none; background: transparent; }}
    """


def _label_for_target(target: ProfileTarget) -> str:
    metadata = target.metadata or {}
    label = metadata.get("label") or metadata.get("name") or target.artifact_type.replace("_", " ").title()
    return _safe_text(label, 80)


def _target_is_source_upload(target: ProfileTarget) -> bool:
    metadata = target.metadata or {}
    kind = str(target.kind or "").lower()
    return bool(kind in SOURCE_UPLOAD_KINDS or metadata.get("source_upload") is True or metadata.get("upload_source") is True)


def _category_for_target(target: ProfileTarget) -> str:
    metadata = target.metadata or {}
    category = metadata.get("category") or metadata.get("group")
    if category:
        return _safe_text(category, 40).title()
    if _target_is_source_upload(target):
        return "Evidence Sources"
    artifact = target.artifact_type.lower()
    if artifact.startswith("mobile_android"):
        return "Android"
    if artifact.startswith("mobile_ios"):
        return "iOS"
    if artifact.startswith("linux"):
        return "Linux"
    if artifact.startswith("macos"):
        return "macOS"
    if artifact.startswith("ai_"):
        return "AI Activity"
    return "Windows"


def _target_hint(target: ProfileTarget) -> str:
    metadata = target.metadata or {}
    parts = []
    if metadata.get("description"):
        parts.append(str(metadata["description"]))
    parts.append(f"Artifact: {target.artifact_type}")
    if target.kind:
        parts.append(f"Mode: {target.kind}")
    if target.max_bytes:
        parts.append(f"Max size: {target.max_bytes} bytes")
    return " | ".join(parts)


class CollectorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.client: ServiceClient | None = None
        self.session = None
        self.profile: CollectionProfile | None = None
        self.consent_accepted = False
        self.target_checks: dict[str, QCheckBox] = {}
        self.targets_by_artifact: dict[str, ProfileTarget] = {}
        self.source_entries: list[dict[str, Any]] = []
        self.device_entries: dict[str, DeviceInfo] = {}
        self._rendering_devices = False
        self._build()
        self._set_running(False)
        self._update_source_summary()
        self._update_privilege_status()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll_events)
        self.timer.start(100)
        self._refresh_devices()
        QTimer.singleShot(700, lambda: self._check_updates(silent=True))

    def _build(self) -> None:
        self.setWindowTitle("unJaena Collector")
        self.setMinimumSize(1060, 720)
        self.setStyleSheet(_stylesheet())

        central = QWidget()
        self.setCentralWidget(central)
        main = QVBoxLayout(central)
        main.setContentsMargins(10, 10, 10, 10)
        main.setSpacing(10)

        header = QFrame()
        header.setObjectName("header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 8, 14, 8)
        title = QLabel("unJaena Collector")
        title.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        header_layout.addWidget(title)
        subtitle = QLabel("Evidence collection, device discovery, and secure upload")
        subtitle.setObjectName("muted")
        header_layout.addWidget(subtitle)
        header_layout.addStretch()
        self.privilege_status = QLabel("Checking access level")
        self.privilege_status.setObjectName("statusWarn")
        header_layout.addWidget(self.privilege_status)
        self.restart_admin_btn = QPushButton("Restart with administrator access")
        self.restart_admin_btn.clicked.connect(self._restart_as_admin)
        header_layout.addWidget(self.restart_admin_btn)
        self.update_status = QLabel("Checking for updates")
        self.update_status.setObjectName("muted")
        header_layout.addWidget(self.update_status)
        self.header_status = QLabel("Ready")
        self.header_status.setObjectName("statusWarn")
        header_layout.addWidget(self.header_status)
        main.addWidget(header)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._left_panel())
        splitter.addWidget(self._right_panel())
        splitter.setSizes([680, 380])
        main.addWidget(splitter, 1)

    def _left_panel(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(8)

        source_group = QGroupBox("0. Evidence Sources")
        source_layout = QVBoxLayout(source_group)

        device_header = QHBoxLayout()
        device_header.addWidget(QLabel("Detected devices"))
        device_header.addStretch()
        self.refresh_devices_btn = QPushButton("Refresh")
        self.refresh_devices_btn.clicked.connect(self._refresh_devices)
        device_header.addWidget(self.refresh_devices_btn)
        source_layout.addLayout(device_header)

        self.device_list = QListWidget()
        self.device_list.setMinimumHeight(146)
        self.device_list.itemChanged.connect(lambda _item: (self._update_source_summary(), self._update_start_state()))
        source_layout.addWidget(self.device_list)
        self.device_summary = QLabel("Scanning devices")
        self.device_summary.setObjectName("muted")
        self.device_summary.setWordWrap(True)
        source_layout.addWidget(self.device_summary)

        self.local_live_cb = QCheckBox("Collect selected local filesystem devices")
        self.local_live_cb.setChecked(False)
        self.local_live_cb.setVisible(False)

        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Manual source type"))
        self.source_type_combo = QComboBox()
        self.source_type_combo.addItem("Auto detect", "")
        for label, artifact_type in SOURCE_TYPE_OPTIONS:
            self.source_type_combo.addItem(label, artifact_type)
        self.source_type_combo.setToolTip("Use Auto detect for normal sources. Pick a type for extensionless volume images.")
        type_row.addWidget(self.source_type_combo, 1)
        source_layout.addLayout(type_row)

        source_buttons = QHBoxLayout()
        self.add_source_btn = QPushButton("Add Image / Disk")
        self.add_source_btn.clicked.connect(self._add_source_file)
        self.add_bundle_btn = QPushButton("Add Mobile Bundle")
        self.add_bundle_btn.clicked.connect(self._add_mobile_bundle)
        self.remove_source_btn = QPushButton("Remove Selected")
        self.remove_source_btn.clicked.connect(self._remove_source_file)
        self.clear_source_btn = QPushButton("Clear")
        self.clear_source_btn.clicked.connect(self._clear_source_files)
        source_buttons.addWidget(self.add_source_btn, 2)
        source_buttons.addWidget(self.add_bundle_btn, 2)
        source_buttons.addWidget(self.remove_source_btn, 1)
        source_buttons.addWidget(self.clear_source_btn)
        source_layout.addLayout(source_buttons)

        self.source_list = QListWidget()
        self.source_list.setMinimumHeight(104)
        source_layout.addWidget(self.source_list)
        self.source_summary = QLabel("")
        self.source_summary.setObjectName("muted")
        source_layout.addWidget(self.source_summary)
        format_hint = QLabel(
            "Add an evidence image, virtual disk, filesystem image, or mobile extraction bundle. "
            "The service verifies allowed source types after token authentication."
        )
        format_hint.setObjectName("muted")
        format_hint.setWordWrap(True)
        source_layout.addWidget(format_hint)
        layout.addWidget(source_group)

        token_group = QGroupBox("1. Session")
        token_layout = QVBoxLayout(token_group)
        self.server_input = QLineEdit(DEFAULT_SERVER_URL)
        self.server_input.setPlaceholderText("https://app.unjaena.com")
        self.token_input = QLineEdit()
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_input.setPlaceholderText("Paste collection session token")
        token_layout.addWidget(QLabel("Service URL"))
        token_layout.addWidget(self.server_input)
        token_layout.addWidget(QLabel("Session token"))
        token_layout.addWidget(self.token_input)
        token_buttons = QHBoxLayout()
        self.show_token_btn = QPushButton("Show")
        self.show_token_btn.setCheckable(True)
        self.show_token_btn.clicked.connect(self._toggle_token)
        self.validate_btn = QPushButton("Validate Token")
        self.validate_btn.clicked.connect(self._validate_token)
        token_buttons.addWidget(self.show_token_btn)
        token_buttons.addWidget(self.validate_btn)
        token_layout.addLayout(token_buttons)
        self.token_status = QLabel("Not validated")
        self.token_status.setObjectName("muted")
        token_layout.addWidget(self.token_status)
        layout.addWidget(token_group)

        profile_group = QGroupBox("2. Server Verification")
        profile_layout = QVBoxLayout(profile_group)
        self.profile_tabs = QTabWidget()
        placeholder = QLabel("Validate a session token to let the server verify the collection scope.")
        placeholder.setObjectName("muted")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.profile_tabs.addTab(placeholder, "Profile")
        profile_layout.addWidget(self.profile_tabs)
        profile_buttons = QHBoxLayout()
        self.select_all_btn = QPushButton("Select All Tab")
        self.select_all_btn.clicked.connect(lambda: self._set_current_tab_checked(True))
        self.clear_tab_btn = QPushButton("Clear Tab")
        self.clear_tab_btn.clicked.connect(lambda: self._set_current_tab_checked(False))
        self.select_all_btn.setVisible(False)
        self.clear_tab_btn.setVisible(False)
        profile_buttons.addWidget(self.select_all_btn)
        profile_buttons.addWidget(self.clear_tab_btn)
        profile_layout.addLayout(profile_buttons)
        layout.addWidget(profile_group)

        progress_group = QGroupBox("3. Progress")
        progress_layout = QVBoxLayout(progress_group)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        progress_layout.addWidget(self.progress)
        counters = QHBoxLayout()
        self.scanned_label = QLabel("Scanned 0")
        self.uploaded_label = QLabel("Uploaded 0")
        self.skipped_label = QLabel("Skipped 0")
        self.failed_label = QLabel("Failed 0")
        for label in (self.scanned_label, self.uploaded_label, self.skipped_label, self.failed_label):
            label.setObjectName("muted")
            counters.addWidget(label)
        progress_layout.addLayout(counters)
        layout.addWidget(progress_group)

        actions = QHBoxLayout()
        self.start_btn = QPushButton("Start Collection")
        self.start_btn.setObjectName("primary")
        self.start_btn.clicked.connect(self._start)
        self.stop_btn = QPushButton("Stop After Current File")
        self.stop_btn.clicked.connect(self._stop)
        actions.addWidget(self.start_btn, 2)
        actions.addWidget(self.stop_btn, 1)
        layout.addLayout(actions)
        layout.addStretch()
        scroll.setWidget(panel)
        return scroll

    def _right_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        group = QGroupBox("Activity Log")
        group_layout = QVBoxLayout(group)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont("Consolas", 9))
        group_layout.addWidget(self.log)
        layout.addWidget(group)
        return panel

    def _update_privilege_status(self) -> None:
        status = privilege_status()
        self.privilege_status.setText(
            "Running with administrator privileges"
            if status.elevated
            else "Limited access - administrator privileges recommended"
        )
        self.privilege_status.setObjectName("statusOk" if status.elevated else "statusWarn")
        self.privilege_status.setToolTip(status.detail)
        self.privilege_status.style().unpolish(self.privilege_status)
        self.privilege_status.style().polish(self.privilege_status)
        self.restart_admin_btn.setVisible(not status.elevated and status.can_relaunch)
        self._log(status.detail)

    def _restart_as_admin(self) -> None:
        self._log("Requesting administrator relaunch")
        if relaunch_elevated():
            QApplication.quit()
            return
        QMessageBox.warning(
            self,
            "Administrator relaunch failed",
            "Unable to relaunch with administrator privileges. Start unJaena Collector as administrator/root to access physical disks and protected locations.",
        )
        self._log("Administrator relaunch failed")

    def _check_updates(self, silent: bool = True) -> None:
        self.update_status.setText("Checking for updates")
        if not silent:
            self._log("Checking for collector updates")
        threading.Thread(target=self._check_updates_worker, args=(silent,), daemon=True).start()

    def _check_updates_worker(self, silent: bool) -> None:
        try:
            info = check_for_update(__version__)
            self._post("update", {"info": info, "silent": silent})
        except Exception as exc:
            self._post("update_error", {"error": _safe_text(exc, 200), "silent": silent})

    def _handle_update_info(self, info: UpdateInfo, silent: bool) -> None:
        if info.available:
            self.update_status.setText(f"Update available: {info.latest_version}")
            self.update_status.setObjectName("statusWarn")
            self.update_status.style().unpolish(self.update_status)
            self.update_status.style().polish(self.update_status)
            asset = f" ({info.asset.name})" if info.asset else ""
            self._log(f"Update available: {info.current_version} -> {info.latest_version}{asset}")
            answer = QMessageBox.question(
                self,
                "Update available",
                f"unJaena Collector {info.latest_version} is available. Download the update now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer == QMessageBox.StandardButton.Yes:
                if open_update(info):
                    self._log("Opened update download")
                else:
                    self._log("Failed to open update download")
            return
        if not silent:
            QMessageBox.information(self, "No update available", f"unJaena Collector {info.current_version} is current.")
        self.update_status.setText(f"Collector is current: {info.current_version}")
        self.update_status.setObjectName("muted")
        self.update_status.style().unpolish(self.update_status)
        self.update_status.style().polish(self.update_status)
        self._log(f"Collector is current: {info.current_version}")

    def _toggle_token(self) -> None:
        self.token_input.setEchoMode(QLineEdit.EchoMode.Normal if self.show_token_btn.isChecked() else QLineEdit.EchoMode.Password)
        self.show_token_btn.setText("Hide" if self.show_token_btn.isChecked() else "Show")

    def _refresh_devices(self) -> None:
        self.refresh_devices_btn.setEnabled(False)
        self.device_summary.setText("Scanning devices")
        threading.Thread(target=self._refresh_devices_worker, daemon=True).start()

    def _refresh_devices_worker(self) -> None:
        try:
            devices, diagnostics = discover_devices()
            self._post("devices", {"devices": devices, "diagnostics": diagnostics})
        except Exception as exc:
            self._post("device_error", _safe_text(exc, 240))

    def _render_devices(self, devices: list[DeviceInfo], diagnostics: list[str]) -> None:
        previously_checked = {device.device_id for device in self._selected_detected_devices()}
        self._rendering_devices = True
        self.device_entries = {device.device_id: device for device in devices}
        self.device_list.clear()
        for device in devices:
            status = device.status.title()
            size = f" | {device.size_label}" if device.size_label else ""
            text = f"{device.label} | {status}{size}"
            item = QListWidgetItem(text, self.device_list)
            flags = item.flags() | Qt.ItemFlag.ItemIsUserCheckable
            if not device.selectable:
                flags = flags & ~Qt.ItemFlag.ItemIsEnabled
            item.setFlags(flags)
            checked = device.device_id in previously_checked
            item.setCheckState(Qt.CheckState.Checked if checked and device.selectable else Qt.CheckState.Unchecked)
            item.setData(Qt.ItemDataRole.UserRole, device.device_id)
            item.setToolTip(device.detail or device.kind)
        self._rendering_devices = False
        parts = [f"{len(devices)} device(s) detected"]
        parts.extend(item for item in diagnostics if item)
        self.device_summary.setText(" | ".join(parts))
        self._log(f"Device scan completed: {len(devices)} device(s)")
        for item in diagnostics:
            if item:
                self._log(item)
        self.refresh_devices_btn.setEnabled(True)
        self._update_source_summary()
        self._update_start_state()

    def _selected_detected_devices(self) -> list[DeviceInfo]:
        selected: list[DeviceInfo] = []
        if not hasattr(self, "device_list"):
            return selected
        for index in range(self.device_list.count()):
            item = self.device_list.item(index)
            if item.checkState() != Qt.CheckState.Checked:
                continue
            device_id = item.data(Qt.ItemDataRole.UserRole)
            device = self.device_entries.get(str(device_id))
            if device:
                selected.append(device)
        return selected

    def _has_selected_live_device(self) -> bool:
        return any(device.live_local for device in self._selected_detected_devices())

    def _add_source_file(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Select evidence image, virtual disk, filesystem image, or bundle", "", SOURCE_FILE_FILTER)
        forced = str(self.source_type_combo.currentData() or "") or None
        skipped = []
        for item in files:
            path = Path(item)
            if any(entry["path"] == path for entry in self.source_entries):
                continue
            source_format = classify_source_path(path, forced)
            if source_format is None:
                skipped.append(path.name)
                continue
            entry = {"path": path, "artifact_type": source_format.artifact_type, "label": source_format.label}
            self.source_entries.append(entry)
            text = f"{source_format.label} | {path.name} | {format_file_size(path)}"
            list_item = QListWidgetItem(text, self.source_list)
            list_item.setToolTip(str(path))
        if skipped:
            QMessageBox.warning(
                self,
                "Source type required",
                "Some files need an explicit Source type selection before they can be added:\n" + "\n".join(skipped[:8]),
            )
        self._update_source_summary()
        self._update_start_state()

    def _add_mobile_bundle(self) -> None:
        previous = self.source_type_combo.currentIndex()
        for index in range(self.source_type_combo.count()):
            if self.source_type_combo.itemData(index) == "mobile_ffs_bundle":
                self.source_type_combo.setCurrentIndex(index)
                break
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select mobile extraction bundle",
            "",
            "Mobile extraction bundles (*.zip *.ufdr *.UFDR *.clbx *.CLBX *.tar *.tgz *.tar.gz *.7z);;All Files (*)",
        )
        forced = "mobile_ffs_bundle"
        skipped = []
        for item in files:
            path = Path(item)
            if any(entry["path"] == path for entry in self.source_entries):
                continue
            source_format = classify_source_path(path, forced)
            if source_format is None:
                skipped.append(path.name)
                continue
            self.source_entries.append({"path": path, "artifact_type": source_format.artifact_type, "label": source_format.label})
            text = f"{source_format.label} | {path.name} | {format_file_size(path)}"
            list_item = QListWidgetItem(text, self.source_list)
            list_item.setToolTip(str(path))
        self.source_type_combo.setCurrentIndex(previous)
        if skipped:
            QMessageBox.warning(self, "Unsupported bundle", "Unsupported file(s):\n" + "\n".join(skipped[:8]))
        self._update_source_summary()
        self._update_start_state()

    def _remove_source_file(self) -> None:
        rows = sorted({idx.row() for idx in self.source_list.selectedIndexes()}, reverse=True)
        for row in rows:
            self.source_entries.pop(row)
            self.source_list.takeItem(row)
        self._update_source_summary()
        self._update_start_state()

    def _clear_source_files(self) -> None:
        self.source_entries.clear()
        self.source_list.clear()
        self._update_source_summary()
        self._update_start_state()

    def _update_source_summary(self) -> None:
        selected_devices = self._selected_detected_devices()
        live_count = sum(1 for device in selected_devices if device.live_local)
        direct_mobile = sum(1 for device in selected_devices if device.kind in {"android_usb", "ios_usb"})
        parts = []
        if live_count:
            parts.append(f"{live_count} live filesystem source(s)")
        if direct_mobile:
            parts.append(f"{direct_mobile} mobile USB device(s) selected")
        parts.append(f"{len(self.source_entries)} source file(s) selected")
        self.source_summary.setText(" | ".join(parts))

    def _set_running(self, running: bool) -> None:
        self.validate_btn.setEnabled(not running)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(running)
        self.server_input.setEnabled(not running)
        self.token_input.setEnabled(not running)
        self.source_type_combo.setEnabled(not running)
        self.device_list.setEnabled(not running)
        self.refresh_devices_btn.setEnabled(not running)
        self.add_source_btn.setEnabled(not running)
        self.add_bundle_btn.setEnabled(not running)
        self.remove_source_btn.setEnabled(not running)
        self.clear_source_btn.setEnabled(not running)
        self.progress.setVisible(running)
        if running:
            header_text = "Collecting"
            header_object = "statusWarn"
        elif self.consent_accepted:
            header_text = "Ready to collect"
            header_object = "statusOk"
        elif self.profile:
            header_text = "Consent required"
            header_object = "statusWarn"
        else:
            header_text = "Ready"
            header_object = "statusWarn"
        self.header_status.setText(header_text)
        self.header_status.setObjectName(header_object)
        self.header_status.style().unpolish(self.header_status)
        self.header_status.style().polish(self.header_status)

    def _selected_artifacts(self) -> set[str]:
        if self.profile and not self.target_checks:
            return set(self.targets_by_artifact)
        return {artifact for artifact, cb in self.target_checks.items() if cb.isChecked()}

    def _selected_has_non_source_target(self) -> bool:
        selected = self._selected_artifacts()
        return any(not _target_is_source_upload(self.targets_by_artifact[artifact]) for artifact in selected if artifact in self.targets_by_artifact)

    def _selected_source_artifacts(self) -> set[str]:
        selected = self._selected_artifacts()
        return {artifact for artifact in selected if artifact in self.targets_by_artifact and _target_is_source_upload(self.targets_by_artifact[artifact])}

    def _update_start_state(self) -> None:
        if self.profile is None or not self.consent_accepted or self.worker and self.worker.is_alive():
            self.start_btn.setEnabled(False)
            return
        selected = self._selected_artifacts()
        if not selected:
            self.start_btn.setEnabled(False)
            return
        has_valid_live = self._has_selected_live_device() and self._selected_has_non_source_target()
        selected_source_artifacts = self._selected_source_artifacts()
        has_valid_sources = bool(self.source_entries) and all(entry["artifact_type"] in selected_source_artifacts for entry in self.source_entries)
        self.start_btn.setEnabled(has_valid_live or has_valid_sources)

    def _log(self, message: str) -> None:
        self.log.append(f"[{time.strftime('%H:%M:%S')}] {_safe_text(message, 500)}")

    def _post(self, kind: str, payload: Any = None) -> None:
        self.events.put((kind, payload))

    def _validate_token(self) -> None:
        server = self.server_input.text().strip().rstrip("/")
        token = self.token_input.text().strip()
        if not server:
            QMessageBox.warning(self, "Missing service URL", "Enter the service URL.")
            return
        if not token:
            QMessageBox.warning(self, "Missing token", "Enter the collection session token.")
            return
        self.consent_accepted = False
        self.validate_btn.setEnabled(False)
        self.token_status.setText("Validating token with server")
        self._log("Validating session token")
        threading.Thread(target=self._validate_worker, args=(server, token), daemon=True).start()

    def _validate_worker(self, server: str, token: str) -> None:
        try:
            client = ServiceClient(server)
            session = client.authenticate(token)
            profile = client.get_profile(session)
            consent_template = client.get_consent_template("en")
            self._post("validated", {"client": client, "session": session, "profile": profile, "consent_template": consent_template})
        except Exception as exc:
            self._post("validate_error", _safe_text(exc, 240))

    def _show_consent_dialog(self, template: dict[str, Any]) -> bool:
        dialog = QDialog(self)
        dialog.setWindowTitle(str(template.get("title") or "Collection consent"))
        dialog.setMinimumWidth(560)
        layout = QVBoxLayout(dialog)

        summary_text = str(template.get("summary") or "Review and accept the collection consent before uploading evidence.")
        summary = QLabel(summary_text)
        summary.setWordWrap(True)
        layout.addWidget(summary)

        body = QTextEdit()
        body.setReadOnly(True)
        body.setMinimumHeight(220)
        body.setPlainText(str(template.get("content") or summary_text))
        layout.addWidget(body)

        checks: list[QCheckBox] = []
        for item in template.get("required_checkboxes") or []:
            cb = QCheckBox(str(item))
            checks.append(cb)
            layout.addWidget(cb)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)

        def sync_ok() -> None:
            ok_button.setEnabled(all(cb.isChecked() for cb in checks))

        for cb in checks:
            cb.stateChanged.connect(lambda _state: sync_ok())
        sync_ok()

        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        return dialog.exec() == QDialog.DialogCode.Accepted

    def _accept_consent_worker(self, template: dict[str, Any]) -> None:
        try:
            if not self.client or not self.session:
                raise RuntimeError("Session is not available")
            result = self.client.accept_consent(self.session, template)
            self._post("consent_accepted", result)
        except Exception as exc:
            self._post("consent_error", _safe_text(exc, 240))

    def _render_profile(self) -> None:
        self.profile_tabs.clear()
        self.target_checks.clear()
        self.targets_by_artifact.clear()
        for target in self.profile.targets if self.profile else []:
            self.targets_by_artifact[target.artifact_type] = target
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(12, 12, 12, 12)
        content_layout.setSpacing(8)
        if not self.targets_by_artifact:
            title = QLabel("Server verified the token, but no collection targets are authorized.")
            title.setObjectName("statusWarn")
        else:
            title = QLabel("Server verified this token and authorized collection for this case.")
            title.setObjectName("statusOk")
        title.setWordWrap(True)
        content_layout.addWidget(title)
        detail = QLabel(
            "Specific artifact rules are enforced by the service and are not displayed in the public collector. "
            "Choose evidence sources below; unauthorized source types will be rejected before upload."
        )
        detail.setObjectName("muted")
        detail.setWordWrap(True)
        content_layout.addWidget(detail)
        content_layout.addStretch()
        self.profile_tabs.addTab(content, "Verified")

    def _set_current_tab_checked(self, checked: bool) -> None:
        current = self.profile_tabs.currentWidget()
        if current is None:
            return
        for cb in current.findChildren(QCheckBox):
            if cb.isEnabled():
                cb.setChecked(checked)
        self._update_start_state()

    def _source_paths(self) -> list[Path]:
        return [entry["path"] for entry in self.source_entries]

    def _source_artifact_map(self) -> dict[str, str]:
        mapping = {}
        for entry in self.source_entries:
            path = entry["path"]
            artifact_type = str(entry["artifact_type"])
            mapping[str(path)] = artifact_type
            try:
                mapping[str(path.resolve())] = artifact_type
            except OSError:
                pass
        return mapping

    def _start(self) -> None:
        if not self.client or not self.session or not self.profile:
            QMessageBox.warning(self, "Session required", "Validate a session token first.")
            return
        if not self.consent_accepted:
            QMessageBox.warning(self, "Consent required", "Complete the collection consent step before starting collection.")
            return
        selected = self._selected_artifacts()
        if not selected:
            QMessageBox.warning(self, "Server authorization required", "This token does not authorize any collection target.")
            return
        source_artifacts = self._selected_source_artifacts()
        missing_source_targets = sorted({entry["artifact_type"] for entry in self.source_entries if entry["artifact_type"] not in source_artifacts})
        if missing_source_targets:
            QMessageBox.warning(
                self,
                "Source type not authorized",
                "This session token does not authorize the selected source type(s): " + ", ".join(missing_source_targets),
            )
            return
        selected_devices = self._selected_detected_devices()
        selected_direct_mobile = [device for device in selected_devices if device.kind in {"android_usb", "ios_usb"}]
        if self._has_selected_live_device() and not self._selected_has_non_source_target() and not self.source_entries:
            QMessageBox.warning(self, "Live collection not authorized", "This session token does not authorize live filesystem collection.")
            return
        if selected_direct_mobile and not self.source_entries and not self._has_selected_live_device():
            QMessageBox.information(
                self,
                "Mobile source required",
                "USB mobile devices are detected here for operator visibility. For this public client build, add an authorized UFDR/CLBX/FFS bundle or iOS backup export so the server can parse it under the signed profile.",
            )
            return
        if not self._has_selected_live_device() and not self.source_entries:
            QMessageBox.warning(self, "Source required", "Select a local filesystem source or add an evidence source file.")
            return
        self.stop_event.clear()
        self._set_running(True)
        self._log("Starting collection")
        self.worker = threading.Thread(
            target=self._run_worker,
            args=(selected, self._source_paths(), self._has_selected_live_device(), self._source_artifact_map()),
            daemon=True,
        )
        self.worker.start()

    def _stop(self) -> None:
        self.stop_event.set()
        self._log("Stop requested")

    def _run_worker(self, selected: set[str], sources: list[Path], include_local: bool, source_artifacts: dict[str, str]) -> None:
        try:
            runner = ProfileRunner(
                self.client,
                self.session,
                self.profile,
                on_event=lambda e: self._post("runner", e),
                should_stop=self.stop_event.is_set,
            )
            result = runner.run(
                selected_artifacts=selected,
                source_files=sources,
                include_local_profile_targets=include_local,
                source_artifacts=source_artifacts,
            )
            self._post("done", result)
        except Exception as exc:
            self._post("error", _safe_text(exc, 240))

    def _poll_events(self) -> None:
        while True:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "validated":
                self.client = payload["client"]
                self.session = payload["session"]
                self.profile = payload["profile"]
                self.consent_accepted = False
                self.token_status.setText(f"Token verified by server - Case {self.session.case_id[:8]}")
                self.token_status.setObjectName("statusOk")
                self.token_status.style().unpolish(self.token_status)
                self.token_status.style().polish(self.token_status)
                self._log(f"Server verified collection scope: {len(self.profile.targets)} authorized target(s)")
                self._render_profile()
                self._set_running(False)
                self._update_start_state()
                if self._show_consent_dialog(dict(payload.get("consent_template") or {})):
                    self.validate_btn.setEnabled(False)
                    self.token_status.setText("Recording collection consent with server")
                    self._log("Recording collection consent")
                    threading.Thread(target=self._accept_consent_worker, args=(dict(payload.get("consent_template") or {}),), daemon=True).start()
                else:
                    self.token_status.setText("Consent required before collection")
                    self.token_status.setObjectName("statusWarn")
                    self.token_status.style().unpolish(self.token_status)
                    self.token_status.style().polish(self.token_status)
                    self._log("Collection consent was not accepted")
                    self.validate_btn.setEnabled(True)
            elif kind == "devices":
                data = dict(payload or {})
                self._render_devices(list(data.get("devices") or []), list(data.get("diagnostics") or []))
            elif kind == "device_error":
                self.refresh_devices_btn.setEnabled(True)
                self.device_summary.setText(f"Device scan failed: {payload}")
                self._log(f"Device scan failed: {payload}")
            elif kind == "update":
                data = dict(payload or {})
                self._handle_update_info(data["info"], bool(data.get("silent", True)))
            elif kind == "update_error":
                data = dict(payload or {})
                self.update_status.setText("Update check unavailable")
                self.update_status.setObjectName("statusWarn")
                self.update_status.style().unpolish(self.update_status)
                self.update_status.style().polish(self.update_status)
                if not data.get("silent", True):
                    QMessageBox.warning(self, "Update check failed", _safe_text(data.get("error"), 200))
                self._log(f"Update check failed: {_safe_text(data.get('error'), 200)}")
            elif kind == "consent_accepted":
                self.consent_accepted = True
                self.token_status.setText("Server verified token and recorded collection consent")
                self.token_status.setObjectName("statusOk")
                self.token_status.style().unpolish(self.token_status)
                self.token_status.style().polish(self.token_status)
                self._log("Collection consent recorded by server")
                self._set_running(False)
                self._update_start_state()
                self.validate_btn.setEnabled(True)
            elif kind == "consent_error":
                self.consent_accepted = False
                self.token_status.setText("Consent could not be recorded")
                self.token_status.setObjectName("statusError")
                self.token_status.style().unpolish(self.token_status)
                self.token_status.style().polish(self.token_status)
                self._log(f"Consent failed: {payload}")
                self._set_running(False)
                self.validate_btn.setEnabled(True)
                QMessageBox.warning(self, "Consent failed", _safe_text(payload, 240))
            elif kind == "validate_error":
                self.consent_accepted = False
                self.token_status.setText("Invalid")
                self.token_status.setObjectName("statusError")
                self.token_status.style().unpolish(self.token_status)
                self.token_status.style().polish(self.token_status)
                self._log(f"Validation failed: {payload}")
                self.validate_btn.setEnabled(True)
                QMessageBox.warning(self, "Validation failed", _safe_text(payload, 240))
            elif kind == "runner":
                self._handle_runner_event(dict(payload or {}))
            elif kind == "done":
                self._handle_done(dict(payload or {}))
            elif kind == "error":
                self._log(f"Collection failed: {payload}")
                self._set_running(False)
                QMessageBox.critical(self, "Collection failed", _safe_text(payload, 240))

    def _handle_runner_event(self, event: dict[str, Any]) -> None:
        for key, label in (("scanned", self.scanned_label), ("uploaded", self.uploaded_label), ("skipped", self.skipped_label), ("failed", self.failed_label)):
            if key in event:
                label.setText(f"{key.title()} {event[key]}")
        name = _safe_text(event.get("name"), 80)
        kind = event.get("event")
        if kind == "started":
            self._log("Server collection authorization accepted")
        elif kind == "target_started":
            self._log(f"Target: {_safe_text(event.get('artifact_type'), 80)}")
        elif kind == "hashing":
            self._log(f"Hashing {name}")
        elif kind == "protecting":
            self._log(f"Encrypting {name}")
        elif kind == "uploading":
            self._log(f"Uploading {name}")
        elif kind == "file_uploaded":
            self._log(f"Uploaded {name}")
        elif kind == "file_skipped":
            self._log(f"Skipped {name}")
        elif kind == "file_failed":
            self._log(f"Failed {name}: {_safe_text(event.get('error'), 140)}")
        elif kind == "stopped":
            self._log("Collection stopped")
        elif kind == "finished":
            self._log("Collection finished")

    def _handle_done(self, result: dict[str, Any]) -> None:
        self.scanned_label.setText(f"Scanned {result.get('scanned', 0)}")
        self.uploaded_label.setText(f"Uploaded {result.get('uploaded', 0)}")
        self.skipped_label.setText(f"Skipped {result.get('skipped', 0)}")
        self.failed_label.setText(f"Failed {result.get('failed', 0)}")
        self._set_running(False)
        self._update_start_state()
        self._log("Done")


def main() -> int:
    if QApplication is None:
        print("PyQt6 desktop support is not available in this Python runtime.", file=sys.stderr)
        return 1
    app = QApplication(sys.argv)
    app.setApplicationName("unJaena Collector")
    window = CollectorApp()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
