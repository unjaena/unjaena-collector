#!/usr/bin/env python3
"""Headless GUI workflow smoke checks for the public collector."""
from __future__ import annotations

import os
import sys
import tempfile
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEventLoop, QTimer, Qt
from PyQt6.QtWidgets import QApplication, QMessageBox

import gui.app as app_module
from gui.app import ARTIFACT_TYPES, CollectionWorker, CollectorWindow
from gui.consent_dialog import ConsentDialog
from core.device_manager import DeviceStatus, DeviceType, UnifiedDeviceInfo, UnifiedDeviceManager


PROFILE_ARTIFACTS = [
    ("windows_smoke", "windows", "system"),
    ("windows_target_b", "windows", "system"),
    ("windows_target_c", "windows", "system"),
    ("android_smoke", "android", "basic"),
    ("ios_smoke", "ios", "core"),
    ("ios_target_b", "ios", "core"),
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

    logical = _device(DeviceType.WINDOWS_LOGICAL_DRIVE, "windows-volume-c")
    window._apply_selected_source_scope([logical], force=True)
    assert window.artifact_checks["windows_smoke"].isEnabled()
    assert window.artifact_checks["windows_smoke"].isChecked()
    for artifact_type in ("android_smoke", "ios_smoke", "linux_smoke", "macos_smoke"):
        cb = window.artifact_checks[artifact_type]
        assert not cb.isChecked(), f"{artifact_type} still checked for Windows logical drive"
        assert not cb.isEnabled(), f"{artifact_type} still enabled for Windows logical drive"

    ios = _device(DeviceType.IOS_DEVICE, "ios-usb")
    window._apply_selected_source_scope([ios], force=True)
    assert window.artifact_checks["ios_smoke"].isEnabled()
    assert window.artifact_checks["ios_smoke"].isChecked()
    for artifact_type in ("windows_smoke", "android_smoke", "linux_smoke", "macos_smoke"):
        cb = window.artifact_checks[artifact_type]
        assert not cb.isChecked(), f"{artifact_type} still checked for iOS-only source"
        assert not cb.isEnabled(), f"{artifact_type} still enabled for iOS-only source"

    unsupported = _device(None, "unsupported-source")
    window._apply_selected_source_scope([unsupported], force=True)
    for artifact_type, _, _ in PROFILE_ARTIFACTS:
        cb = window.artifact_checks[artifact_type]
        assert cb.isEnabled(), f"{artifact_type} disabled for unsupported source"
        assert cb.isChecked(), f"{artifact_type} unchecked for unsupported source"



def _assert_artifact_selection_matrix(window: CollectorWindow) -> None:
    window.session_id = "session-id"
    window.collection_token = "collection-token"
    window.case_id = "case-id"
    window._allow_all_artifacts = True
    window._mapped_allowed_artifacts = set(ARTIFACT_TYPES)
    window.device_manager.get_selected_devices = lambda: [
        _device(DeviceType.WINDOWS_LOGICAL_DRIVE, "windows-volume-c")
    ]

    window._update_platform_tab_states()
    window.artifacts_tab.setCurrentIndex(0)
    windows = ["windows_smoke", "windows_target_b", "windows_target_c"]
    non_windows = ["android_smoke", "ios_smoke", "ios_target_b", "linux_smoke", "macos_smoke"]

    for artifact_type in windows:
        assert window.artifact_checks[artifact_type].isEnabled(), f"{artifact_type} not enabled for Windows source"
    for artifact_type in non_windows:
        cb = window.artifact_checks[artifact_type]
        assert not cb.isEnabled(), f"{artifact_type} enabled for Windows source"
        assert not cb.isChecked(), f"{artifact_type} checked for Windows source"

    for artifact_type in windows:
        window.artifact_checks[artifact_type].setChecked(False)
    assert window._selected_artifact_types() == []
    window._update_collect_button_state()
    assert not window.collect_btn.isEnabled(), "Start Collection enabled with zero selected artifacts"

    window.artifact_checks["windows_smoke"].setChecked(True)
    assert set(window._selected_artifact_types()) == {"windows_smoke"}
    window._update_collect_button_state()
    assert window.collect_btn.isEnabled(), "single selected artifact did not enable Start Collection"

    window.artifact_checks["windows_target_b"].setChecked(True)
    assert set(window._selected_artifact_types()) == {"windows_smoke", "windows_target_b"}

    window.artifact_checks["windows_target_c"].setEnabled(False)
    window.artifact_checks["windows_target_c"].setChecked(True)
    assert set(window._selected_artifact_types()) == {"windows_smoke", "windows_target_b"}, (
        "disabled checked artifact leaked into selected collection targets"
    )
    window.artifact_checks["windows_target_c"].setChecked(False)
    window.artifact_checks["windows_target_c"].setEnabled(True)

    for artifact_type in windows:
        window.artifact_checks[artifact_type].setChecked(False)
    window.select_all_cb.setEnabled(True)
    window.select_all_cb.blockSignals(True)
    window.select_all_cb.setChecked(False)
    window.select_all_cb.blockSignals(False)
    window.select_all_cb.setChecked(True)
    assert set(window._selected_artifact_types()) == set(windows), "Select All current tab did not select all Windows targets"
    for artifact_type in non_windows:
        assert not window.artifact_checks[artifact_type].isChecked(), f"Select All changed non-current-tab target {artifact_type}"

    window.select_all_cb.setChecked(False)
    assert window._selected_artifact_types() == [], "Select All clear did not clear current tab targets"

    window._allow_all_artifacts = False
    window._mapped_allowed_artifacts = {"windows_target_b"}
    window._apply_selected_source_scope(window.device_manager.get_selected_devices(), force=True)
    assert window.artifact_checks["windows_target_b"].isEnabled()
    assert window.artifact_checks["windows_target_b"].isChecked()
    assert set(window._selected_artifact_types()) == {"windows_target_b"}
    for artifact_type in ("windows_smoke", "windows_target_c"):
        cb = window.artifact_checks[artifact_type]
        assert not cb.isEnabled(), f"token-disallowed target {artifact_type} remained enabled"
        assert not cb.isChecked(), f"token-disallowed target {artifact_type} remained checked"

    window._allow_all_artifacts = True
    window._mapped_allowed_artifacts = set(ARTIFACT_TYPES)
    window.device_manager.get_selected_devices = lambda: [_device(DeviceType.IOS_DEVICE, "ios-usb")]
    window._update_platform_tab_states()
    assert set(window._selected_artifact_types()) == {"ios_smoke", "ios_target_b"}
    for artifact_type in windows:
        cb = window.artifact_checks[artifact_type]
        assert not cb.isEnabled(), f"Windows target {artifact_type} enabled for iOS source"
        assert not cb.isChecked(), f"Windows target {artifact_type} still checked after iOS source selection"

def _assert_artifact_actions_update_start_button(window: CollectorWindow) -> None:
    window.collection_token = "collection-token"
    window.device_manager.get_selected_devices = lambda: [
        _device(DeviceType.E01_IMAGE, "windows.E01", "windows")
    ]

    for cb in window.artifact_checks.values():
        cb.setEnabled(False)
        cb.setChecked(False)

    windows_cb = window.artifact_checks["windows_smoke"]
    windows_cb.setEnabled(False)
    windows_cb.setChecked(True)
    window._update_collect_button_state()
    assert not window.collect_btn.isEnabled(), "disabled checked artifact enabled Start Collection"

    windows_cb.setEnabled(True)
    windows_cb.setChecked(False)
    window.artifacts_tab.setCurrentIndex(0)

    window.collect_btn.setEnabled(False)
    window.select_all_cb.setEnabled(True)
    window.select_all_cb.setChecked(False)
    window.select_all_cb.setChecked(True)
    assert windows_cb.isChecked()
    assert window.collect_btn.isEnabled(), "select all did not refresh Start Collection"

    windows_cb.setChecked(False)
    assert not window.collect_btn.isEnabled(), "Start Collection stayed enabled with no artifacts"
    windows_cb.setChecked(True)
    assert window.collect_btn.isEnabled(), "artifact checkbox change did not refresh Start Collection"


def _assert_device_selection_signal_updates_start_button(window: CollectorWindow) -> None:
    window.device_manager.get_selected_devices = UnifiedDeviceManager.get_selected_devices.__get__(
        window.device_manager, UnifiedDeviceManager
    )
    window.collection_token = "collection-token"
    for cb in window.artifact_checks.values():
        cb.setEnabled(False)
        cb.setChecked(False)
    windows_cb = window.artifact_checks["windows_smoke"]
    windows_cb.setEnabled(True)
    windows_cb.setChecked(True)

    device = UnifiedDeviceInfo(
        device_id="physical0",
        device_type=DeviceType.WINDOWS_PHYSICAL_DISK,
        display_name="physical0",
        status=DeviceStatus.READY,
    )
    window.device_manager._devices[device.device_id] = device
    window.device_manager.select_device(device.device_id, True)
    assert window.collect_btn.isEnabled(), "device manager selection did not refresh Start Collection"

    window.device_manager._on_poll_finished([], [])
    assert not window.collect_btn.isEnabled(), "removed selected device left Start Collection enabled"


def _assert_token_profile_waits_for_evidence_source(window: CollectorWindow) -> None:
    window.session_id = "session-id"
    window.collection_token = "collection-token"
    window.case_id = "case-id"
    window._allow_all_artifacts = True
    window._mapped_allowed_artifacts = set(ARTIFACT_TYPES)
    window.device_manager.get_selected_devices = lambda: []

    for cb in window.artifact_checks.values():
        cb.setEnabled(True)
        cb.setChecked(True)
    window.select_all_cb.setEnabled(True)
    window.include_deleted_cb.setEnabled(True)

    window._update_platform_tab_states()
    assert "Authorized profile loaded" in window.source_scope_label.text()
    assert not window.select_all_cb.isEnabled(), "Select All should wait for an evidence source"
    assert not window.include_deleted_cb.isEnabled(), "Include deleted should wait for an evidence source"
    assert not window.collect_btn.isEnabled(), "Start Collection enabled without evidence source"
    for artifact_type, cb in window.artifact_checks.items():
        assert not cb.isEnabled(), f"{artifact_type} enabled before evidence source selection"
        assert not cb.isChecked(), f"{artifact_type} checked before evidence source selection"

    window.device_manager.get_selected_devices = lambda: [
        _device(DeviceType.E01_IMAGE, "windows.E01", "windows")
    ]
    window._update_platform_tab_states()
    window._update_collect_button_state()
    assert window.artifact_checks["windows_smoke"].isEnabled()
    assert window.artifact_checks["windows_smoke"].isChecked()
    assert window.select_all_cb.isEnabled()
    assert window.include_deleted_cb.isEnabled()
    assert window.collect_btn.isEnabled(), "Start Collection did not enable after source scope was applied"


def _assert_start_path_keeps_selected_artifacts_while_locked(window: CollectorWindow) -> None:
    window.session_id = "session-id"
    window.collection_token = "collection-token"
    window.case_id = "case-id"
    window.device_manager.get_selected_devices = lambda: [
        _device(DeviceType.E01_IMAGE, "windows.E01", "windows")
    ]
    for cb in window.artifact_checks.values():
        cb.setEnabled(False)
        cb.setChecked(False)
    window.artifact_checks["windows_smoke"].setEnabled(True)
    window.artifact_checks["windows_smoke"].setChecked(True)

    window._set_collection_inputs_locked(True)
    try:
        assert "windows_smoke" in window._selected_artifact_types(), (
            "locked parent UI hid checked artifacts from collection start"
        )
    finally:
        window._set_collection_inputs_locked(False)

    original_validator = app_module.TokenValidator
    original_warning = QMessageBox.warning
    original_confirm = window._confirm_collection_plan
    warnings = []
    confirmed_artifacts = []

    def fake_warning(parent, title, body, *args, **kwargs):
        warnings.append((str(title), str(body)))
        return QMessageBox.StandardButton.Ok

    def fake_confirm(devices, artifacts):
        confirmed_artifacts.extend(artifacts)
        return False

    app_module.TokenValidator = lambda server_url: SimpleNamespace(
        validate_session=lambda session_id, token: SimpleNamespace(
            can_proceed=True,
            case_id="case-id",
            case_status="active",
            reason=None,
        )
    )
    QMessageBox.warning = fake_warning
    window._confirm_collection_plan = fake_confirm
    try:
        window._start_collection()
    finally:
        app_module.TokenValidator = original_validator
        QMessageBox.warning = original_warning
        window._confirm_collection_plan = original_confirm
        window._collection_starting = False
        window._collection_running = False
        window._set_collection_inputs_locked(False)
        window._update_collect_button_state()

    assert not any(
        body == "Please select at least one artifact type" for _, body in warnings
    ), "start path rejected checked artifacts while inputs were locked"
    assert "windows_smoke" in confirmed_artifacts, "start path did not carry selected artifacts into plan review"


def _assert_start_preflight_for_supported_sources(window: CollectorWindow) -> None:
    sources = [
        (DeviceType.WINDOWS_PHYSICAL_DISK, "windows-disk", "windows_smoke", None),
        (DeviceType.WINDOWS_LOGICAL_DRIVE, "windows-volume-c", "windows_smoke", None),
        (DeviceType.ANDROID_DEVICE, "android-usb", "android_smoke", None),
        (DeviceType.IOS_DEVICE, "ios-usb", "ios_smoke", None),
        (DeviceType.IOS_BACKUP, "ios-backup", "ios_smoke", None),
        (DeviceType.MOBILE_FFS_BUNDLE_IOS, "ios-ffs", "ios_smoke", None),
        (DeviceType.MOBILE_FFS_BUNDLE_ANDROID, "android-ffs", "android_smoke", None),
        (DeviceType.LINUX_LOCAL_SYSTEM, "linux-live", "linux_smoke", None),
        (DeviceType.MACOS_LOCAL_SYSTEM, "macos-live", "macos_smoke", None),
        (DeviceType.E01_IMAGE, "unknown.E01", "windows_smoke", "unknown"),
    ]
    for device_type, name, expected_artifact, detected_os in sources:
        window.session_id = "session-id"
        window.collection_token = "collection-token"
        window.case_id = "case-id"
        window._allow_all_artifacts = True
        window._mapped_allowed_artifacts = set(ARTIFACT_TYPES)
        window.device_manager.get_selected_devices = lambda d=_device(device_type, name, detected_os): [d]
        for cb in window.artifact_checks.values():
            cb.setEnabled(False)
            cb.setChecked(False)
        window._update_platform_tab_states()
        assert expected_artifact in window._selected_artifact_types(), (
            f"{device_type} did not leave a collectable artifact selected"
        )
        window._set_collection_inputs_locked(True)
        try:
            assert expected_artifact in window._selected_artifact_types(), (
                f"locked start state hid selected artifact for {device_type}"
            )
        finally:
            window._set_collection_inputs_locked(False)


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
    ios = _device(DeviceType.IOS_DEVICE, "ios-usb")
    artifacts = [artifact_type for artifact_type, _, _ in PROFILE_ARTIFACTS]
    worker = CollectionWorker("", "", "", "", "", artifacts, selected_devices=[unknown, windows, ios])
    assert worker._artifacts_for_device(unknown) == artifacts
    assert set(worker._artifacts_for_device(windows)) == {"windows_smoke", "windows_target_b", "windows_target_c"}
    assert set(worker._artifacts_for_device(ios)) == {"ios_smoke", "ios_target_b"}

    label = worker._target_label("windows_discord", 2, 7, "evidence.E01")
    assert label == "[evidence.E01] Selected target 2/7"
    assert "windows_discord" not in label


def _assert_checkbox_widget_visible(dialog: ConsentDialog, checkbox, name: str) -> None:
    assert checkbox is not None, f"{name} checkbox missing"
    assert checkbox.isVisible(), f"{name} checkbox widget is hidden"
    assert 20 <= checkbox.width() <= 24, f"{name} checkbox width is unstable: {checkbox.width()}"
    assert 20 <= checkbox.height() <= 24, f"{name} checkbox height is unstable: {checkbox.height()}"

    parent = checkbox.parentWidget()
    assert parent is not None, f"{name} checkbox has no parent row"
    top_left = checkbox.mapTo(parent, checkbox.rect().topLeft())
    bottom_right = checkbox.mapTo(parent, checkbox.rect().bottomRight())
    assert parent.rect().contains(top_left), f"{name} checkbox top-left is clipped by row"
    assert parent.rect().contains(bottom_right), f"{name} checkbox bottom-right is clipped by row"


def _assert_checkbox_pixels_visible(dialog: ConsentDialog, checkbox, name: str) -> None:
    checkbox.repaint()
    QApplication.processEvents()
    image = dialog.grab().toImage()
    top_left = checkbox.mapTo(dialog, checkbox.rect().topLeft())
    colors = set()
    for x in range(max(0, top_left.x()), min(image.width(), top_left.x() + checkbox.width())):
        for y in range(max(0, top_left.y()), min(image.height(), top_left.y() + checkbox.height())):
            colors.add(image.pixelColor(x, y).name())
            if len(colors) >= 3:
                return
    assert len(colors) >= 3, f"{name} checkbox did not render visible border/fill pixels"


def _assert_footer_is_stable(dialog: ConsentDialog) -> None:
    header_geo = dialog.header_frame.geometry()
    body_geo = dialog.body_scroll.geometry()
    footer_geo = dialog.footer_frame.geometry()
    assert header_geo.bottom() < body_geo.top(), "header overlaps consent body"
    assert body_geo.bottom() < footer_geo.top(), "consent body overlaps fixed footer"
    assert footer_geo.bottom() <= dialog.rect().bottom(), "footer extends outside dialog"

    cancel_geo = dialog.cancel_btn.geometry()
    agree_geo = dialog.agree_btn.geometry()
    assert abs(cancel_geo.y() - agree_geo.y()) <= 1, "footer buttons are not on one row"
    assert not cancel_geo.intersects(agree_geo), "footer buttons overlap"
    assert 36 <= cancel_geo.height() <= 44
    assert 36 <= agree_geo.height() <= 44
    assert agree_geo.width() >= 200
    assert cancel_geo.bottom() <= dialog.footer_frame.rect().bottom()
    assert agree_geo.bottom() <= dialog.footer_frame.rect().bottom()


def _assert_consent_dialog(window: CollectorWindow) -> None:
    dialog = ConsentDialog(parent=window, server_url=None, session_id="session", case_id="case", language="ko")
    dialog._apply_template({
        "id": "smoke-template",
        "version": "smoke",
        "title": "AI Forensic Lab - Data Collection Consent",
        "content": "## Digital Forensic Collection Consent\n\n### Purpose\nThis confirms the scope before collection.",
        "required_checkboxes": [
            "I confirm that I have authority to perform this collection.",
            "I understand that selected evidence sources will be collected and uploaded for analysis.",
            "I understand that collection may include system, file-system, application, event-log, and network artifacts according to the selected profile.",
            "I acknowledge that the collected data will be processed according to the case retention policy and deleted when the retention window expires unless the case is extended.",
            "I agree to start collection for the selected evidence sources.",
        ],
    })
    dialog.show()
    QApplication.processEvents()
    dialog._center_on_screen()
    QApplication.processEvents()

    assert dialog.windowTitle()
    assert hasattr(dialog, "body_scroll")
    assert dialog.body_scroll.horizontalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAlwaysOff
    assert dialog.footer_frame.height() == 64
    _assert_footer_is_stable(dialog)

    assert len(dialog.checkboxes) == 5, "required consent checkbox rows were not created"
    _assert_checkbox_widget_visible(dialog, dialog.transfer_checkbox, "transfer")
    _assert_checkbox_widget_visible(dialog, dialog.checkboxes[0], "first consent")

    viewport_rect = dialog.body_scroll.viewport().rect()
    first_center = dialog.checkboxes[0].mapTo(dialog.body_scroll.viewport(), dialog.checkboxes[0].rect().center())
    assert viewport_rect.contains(first_center), "first consent checkbox is not visible in the initial modal viewport"

    _assert_checkbox_pixels_visible(dialog, dialog.transfer_checkbox, "transfer")
    _assert_checkbox_pixels_visible(dialog, dialog.checkboxes[0], "first consent")

    for cb in dialog.checkboxes:
        cb.setChecked(True)
    dialog.transfer_checkbox.setChecked(True)
    QApplication.processEvents()
    assert dialog.agree_btn.isEnabled(), "agree button did not enable after visible consent checks"
    _assert_footer_is_stable(dialog)

    screenshot_path = os.path.join(tempfile.gettempdir(), "unjaena_consent_dialog_smoke.png")
    assert dialog.grab().save(screenshot_path), f"failed to save consent smoke screenshot: {screenshot_path}"
    dialog.close()


class _SlowEnumerator:
    def enumerate(self):
        time.sleep(0.2)
        return [
            UnifiedDeviceInfo(
                device_id="slow-disk",
                device_type=DeviceType.RAW_IMAGE,
                display_name="slow-disk",
                status=DeviceStatus.READY,
            )
        ]


def _assert_device_polling_is_async() -> None:
    manager = UnifiedDeviceManager()
    manager.register_enumerator("slow", _SlowEnumerator())
    seen = []
    loop = QEventLoop()
    manager.device_added.connect(lambda device: seen.append(device.device_id))
    manager.scan_completed.connect(loop.quit)

    started = time.monotonic()
    manager.refresh()
    elapsed = time.monotonic() - started
    assert elapsed < 0.1, f"device refresh blocked GUI thread for {elapsed:.3f}s"

    QTimer.singleShot(1000, loop.quit)
    loop.exec()
    assert seen == ["slow-disk"], "async device polling did not publish scan results"
    manager.stop_monitoring()


def main() -> int:
    qt_app = QApplication.instance() or QApplication(sys.argv)
    _install_smoke_profile()
    window = _build_window()
    _assert_source_scope(window)
    _assert_artifact_selection_matrix(window)
    _assert_artifact_actions_update_start_button(window)
    _assert_device_selection_signal_updates_start_button(window)
    _assert_token_profile_waits_for_evidence_source(window)
    _assert_start_path_keeps_selected_artifacts_while_locked(window)
    _assert_start_preflight_for_supported_sources(window)
    _assert_plan_dialog(window)
    _assert_start_locking(window)
    _assert_worker_filtering()
    _assert_consent_dialog(window)
    _assert_device_polling_is_async()
    window.close()
    print("collector_gui_workflow_smoke_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
