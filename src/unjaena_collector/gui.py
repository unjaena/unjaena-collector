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
from .models import CollectionProfile, ProfileTarget
from .runner import ProfileRunner
from .device_discovery import DeviceInfo, discover_devices
from .source_formats import (
    SOURCE_FILE_FILTER,
    SOURCE_TYPE_OPTIONS,
    classify_source_path,
    format_file_size,
    supported_format_summary,
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
        self.target_checks: dict[str, QCheckBox] = {}
        self.targets_by_artifact: dict[str, ProfileTarget] = {}
        self.source_entries: list[dict[str, Any]] = []
        self.device_entries: dict[str, DeviceInfo] = {}
        self._rendering_devices = False
        self._build()
        self._set_running(False)
        self._update_source_summary()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll_events)
        self.timer.start(100)
        self._refresh_devices()

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
        format_hint = QLabel(f"Supported: {supported_format_summary()}")
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

        profile_group = QGroupBox("2. Collection Profile")
        profile_layout = QVBoxLayout(profile_group)
        self.profile_tabs = QTabWidget()
        placeholder = QLabel("Validate a session token to load the server-signed collection profile.")
        placeholder.setObjectName("muted")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.profile_tabs.addTab(placeholder, "Profile")
        profile_layout.addWidget(self.profile_tabs)
        profile_buttons = QHBoxLayout()
        self.select_all_btn = QPushButton("Select All Tab")
        self.select_all_btn.clicked.connect(lambda: self._set_current_tab_checked(True))
        self.clear_tab_btn = QPushButton("Clear Tab")
        self.clear_tab_btn.clicked.connect(lambda: self._set_current_tab_checked(False))
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
            checked = device.live_local or device.device_id in previously_checked
            item.setCheckState(Qt.CheckState.Checked if checked and device.selectable else Qt.CheckState.Unchecked)
            item.setData(Qt.ItemDataRole.UserRole, device.device_id)
            item.setToolTip(device.detail or device.kind)
        self._rendering_devices = False
        parts = [f"{len(devices)} device(s) detected"]
        parts.extend(item for item in diagnostics if item)
        self.device_summary.setText(" | ".join(parts))
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
        self.start_btn.setEnabled(not running and self.profile is not None)
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
        self.header_status.setText("Collecting" if running else ("Profile loaded" if self.profile else "Ready"))
        self.header_status.setObjectName("statusWarn" if running else ("statusOk" if self.profile else "statusWarn"))
        self.header_status.style().unpolish(self.header_status)
        self.header_status.style().polish(self.header_status)

    def _selected_artifacts(self) -> set[str]:
        return {artifact for artifact, cb in self.target_checks.items() if cb.isChecked()}

    def _selected_has_non_source_target(self) -> bool:
        selected = self._selected_artifacts()
        return any(not _target_is_source_upload(self.targets_by_artifact[artifact]) for artifact in selected if artifact in self.targets_by_artifact)

    def _selected_source_artifacts(self) -> set[str]:
        selected = self._selected_artifacts()
        return {artifact for artifact in selected if artifact in self.targets_by_artifact and _target_is_source_upload(self.targets_by_artifact[artifact])}

    def _update_start_state(self) -> None:
        if self.profile is None or self.worker and self.worker.is_alive():
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
        self.validate_btn.setEnabled(False)
        self.token_status.setText("Validating")
        self._log("Validating session token")
        threading.Thread(target=self._validate_worker, args=(server, token), daemon=True).start()

    def _validate_worker(self, server: str, token: str) -> None:
        try:
            client = ServiceClient(server)
            session = client.authenticate(token)
            profile = client.get_profile(session)
            self._post("validated", {"client": client, "session": session, "profile": profile})
        except Exception as exc:
            self._post("validate_error", _safe_text(exc, 240))

    def _render_profile(self) -> None:
        self.profile_tabs.clear()
        self.target_checks.clear()
        self.targets_by_artifact.clear()
        grouped: dict[str, list[ProfileTarget]] = {}
        for target in self.profile.targets if self.profile else []:
            self.targets_by_artifact[target.artifact_type] = target
            grouped.setdefault(_category_for_target(target), []).append(target)
        if not grouped:
            label = QLabel("The authenticated server profile contains no collection targets.")
            label.setObjectName("muted")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.profile_tabs.addTab(label, "Profile")
            return
        for category in sorted(grouped):
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            content = QWidget()
            content_layout = QVBoxLayout(content)
            content_layout.setContentsMargins(8, 8, 8, 8)
            content_layout.setSpacing(4)
            for target in grouped[category]:
                cb = QCheckBox(_label_for_target(target))
                cb.setChecked(True)
                cb.setProperty("artifact_type", target.artifact_type)
                cb.setToolTip(_target_hint(target))
                cb.stateChanged.connect(lambda _state: self._update_start_state())
                self.target_checks[target.artifact_type] = cb
                content_layout.addWidget(cb)
            content_layout.addStretch()
            scroll.setWidget(content)
            self.profile_tabs.addTab(scroll, category)

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
        selected = self._selected_artifacts()
        if not selected:
            QMessageBox.warning(self, "Profile target required", "Select at least one server profile target.")
            return
        source_artifacts = self._selected_source_artifacts()
        missing_source_targets = sorted({entry["artifact_type"] for entry in self.source_entries if entry["artifact_type"] not in source_artifacts})
        if missing_source_targets:
            QMessageBox.warning(
                self,
                "Evidence source target required",
                "Enable the matching Evidence Sources profile target for: " + ", ".join(missing_source_targets),
            )
            return
        selected_devices = self._selected_detected_devices()
        selected_direct_mobile = [device for device in selected_devices if device.kind in {"android_usb", "ios_usb"}]
        if self._has_selected_live_device() and not self._selected_has_non_source_target() and not self.source_entries:
            QMessageBox.warning(self, "Profile target required", "Select a non-source profile target for live filesystem collection.")
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
                self.token_status.setText(f"Valid - Case {self.session.case_id[:8]}")
                self.token_status.setObjectName("statusOk")
                self.token_status.style().unpolish(self.token_status)
                self.token_status.style().polish(self.token_status)
                self._log(f"Profile loaded: {len(self.profile.targets)} target(s)")
                self._render_profile()
                self._set_running(False)
                self._update_start_state()
                self.validate_btn.setEnabled(True)
            elif kind == "devices":
                data = dict(payload or {})
                self._render_devices(list(data.get("devices") or []), list(data.get("diagnostics") or []))
            elif kind == "device_error":
                self.refresh_devices_btn.setEnabled(True)
                self.device_summary.setText(f"Device scan failed: {payload}")
                self._log(f"Device scan failed: {payload}")
            elif kind == "validate_error":
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
            self._log("Collection profile accepted")
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
