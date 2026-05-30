#!/usr/bin/env python3
"""Headless GUI workflow smoke checks for the public collector."""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QMessageBox

import gui.app as app_module
from gui.app import ARTIFACT_TYPES, CollectionWorker, CollectorWindow
from gui.consent_dialog import ConsentDialog
from core.device_manager import DeviceType


PROFILE_ARTIFACTS = [
    ("windows_smoke", "windows", "system"),
    ("android_smoke", "android", "basic"),
    ("ios_smoke", "ios", "core"),
    ("linux_smoke", "linux", "system"),
    ("macos_smoke", "macos", "system"),
]


def _install_smoke_profile() -> None:
    for artifact_type, category, subcategory in PROFILE_ARTIFACTS:
        ARTIFACT_TYPES[artifact_type] = {
            "name": artifact_type.replace("_", " ").title(),
            "description": f"{category} smoke artifact",
            "category": category,
            "subcategory": subcategory,
            "default_enabled": True,
        }


def _device(device_type, name, detected_os=None):
    metadata = {}
    if detected_os is not None:
        metadata["detected_os"] = detected_os
    return SimpleNamespace(
        device_id=name,
        device_type=device_type,
        metadata=metadata,
        display_name=name,
        size_display="128 MB",
        requires_admin=False,
    )


def _build_window() -> CollectorWindow:
    app_module.create_default_enumerators = lambda: {}
    CollectorWindow.check_server_connection = lambda self: None
    config = {
        "app_name": "unJaena Collector Smoke",
        "version": "smoke",
        "server_url": "https://app.unjaena.com",
        "ws_url": "wss://app.unjaena.com",
    }
    window = CollectorWindow(config)
    window.device_manager.stop_monitoring()
    window._allow_all_artifacts = True
    window._mapped_allowed_artifacts = set(ARTIFACT_TYPES)
    window._build_artifact_tabs(preserve_index=True)
    for artifact_type, _, _ in PROFILE_ARTIFACTS:
        assert artifact_type in window.artifact_checks, f"missing checkbox: {artifact_type}"
    for cb in window.artifact_checks.values():
        cb.setEnabled(True)
        cb.setChecked(True)
    return window


def _assert_source_scope(window: CollectorWindow) -> None:
    unknown = _device(DeviceType.E01_IMAGE, "unknown-os.E01", "unknown")
    windows = _device(DeviceType.E01_IMAGE, "windows.E01", "windows")

    window._apply_selected_source_scope([unknown], force=True)
    for artifact_type, _, _ in PROFILE_ARTIFACTS:
        cb = window.artifact_checks[artifact_type]
        assert cb.isEnabled(), f"{artifact_type} disabled for unknown image"
        assert cb.isChecked(), f"{artifact_type} unchecked for unknown image"
    window._update_source_scope_status([unknown])
    assert "Full collection scope is enabled" in window.source_scope_label.text()

    window._apply_selected_source_scope([windows], force=True)
    assert window.artifact_checks["windows_smoke"].isEnabled()
    assert window.artifact_checks["windows_smoke"].isChecked()
    for artifact_type in ("android_smoke", "ios_smoke", "linux_smoke", "macos_smoke"):
        cb = window.artifact_checks[artifact_type]
        assert not cb.isChecked(), f"{artifact_type} still checked for Windows-only image"
        assert not cb.isEnabled(), f"{artifact_type} still enabled for Windows-only image"


def _assert_plan_dialog(window: CollectorWindow) -> None:
    unknown = _device(DeviceType.E01_IMAGE, "unknown-os.E01", "unknown")
    windows = _device(DeviceType.E01_IMAGE, "windows.E01", "windows")
    original_question = QMessageBox.question
    captured = {}

    def fake_question(parent, title, body, buttons, default):
        captured["title"] = title
        captured["body"] = body
        return QMessageBox.StandardButton.No

    QMessageBox.question = fake_question
    try:
        accepted = window._confirm_collection_plan([unknown, windows], list(window.artifact_checks.keys()))
    finally:
        QMessageBox.question = original_question

    assert accepted is False
    assert captured["title"] == "Review Collection Plan"
    assert "Unknown - full scope" in captured["body"]
    assert "Multiple evidence sources" in captured["body"]


def _assert_start_locking(window: CollectorWindow) -> None:
    window._collection_starting = False
    window._collection_running = False
    window.collect_btn.setEnabled(True)
    window.validate_btn.setEnabled(True)
    window.cancel_btn.setEnabled(False)
    window._start_collection_impl = lambda: False
    window._start_collection()
    assert not window._collection_starting and not window._collection_running
    assert window.device_group.isEnabled()
    assert window.token_group.isEnabled()
    assert window.artifacts_group.isEnabled()
    assert window.validate_btn.isEnabled()

    window.collect_btn.setEnabled(True)
    window.validate_btn.setEnabled(True)
    window._start_collection_impl = lambda: True
    window._start_collection()
    assert not window._collection_starting and window._collection_running
    assert not window.device_group.isEnabled()
    assert not window.token_group.isEnabled()
    assert not window.artifacts_group.isEnabled()
    assert not window.validate_btn.isEnabled()


def _assert_worker_filtering() -> None:
    unknown = _device(DeviceType.E01_IMAGE, "unknown-os.E01", "unknown")
    windows = _device(DeviceType.E01_IMAGE, "windows.E01", "windows")
    artifacts = [artifact_type for artifact_type, _, _ in PROFILE_ARTIFACTS]
    worker = CollectionWorker("", "", "", "", "", artifacts, selected_devices=[unknown, windows])
    assert worker._artifacts_for_device(unknown) == artifacts
    assert worker._artifacts_for_device(windows) == ["windows_smoke"]


def _assert_consent_dialog(window: CollectorWindow) -> None:
    dialog = ConsentDialog(parent=window, server_url=None, session_id="session", case_id="case", language="en")
    dialog._center_on_screen()
    assert dialog.windowTitle()
    dialog.close()


def main() -> int:
    qt_app = QApplication.instance() or QApplication(sys.argv)
    _install_smoke_profile()
    window = _build_window()
    _assert_source_scope(window)
    _assert_plan_dialog(window)
    _assert_start_locking(window)
    _assert_worker_filtering()
    _assert_consent_dialog(window)
    window.close()
    print("collector_gui_workflow_smoke_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
