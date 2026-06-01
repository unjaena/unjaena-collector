#!/usr/bin/env python3
"""Verify server-issued profiles render collectable targets in the GUI."""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from PyQt6.QtWidgets import QApplication

import gui.app as app_module
from core.collection_profile import apply_collection_profile_to_registry
from gui.app import (
    ANDROID_ARTIFACT_TYPES,
    ARTIFACT_MFT_FILTERS,
    ARTIFACT_TYPES,
    IOS_ARTIFACT_TYPES,
    LINUX_ARTIFACT_TYPES,
    MACOS_ARTIFACT_TYPES,
    CollectorWindow,
)


def _target(artifact_type: str, category: str, subcategory: str = "system") -> dict:
    return {
        "artifact_type": artifact_type,
        "kind": "collector_config",
        "patterns": [],
        "max_bytes": None,
        "metadata": {
            "category": category,
            "label": artifact_type.replace("_", " ").title(),
            "description": "Server-authorized smoke target",
            "collector_config": {
                "subcategory": subcategory,
                "mft_config": {
                    "base_path": "Windows",
                    "pattern": "*.smoke",
                    "path_optional": True,
                },
            },
        },
    }


def _install_profile() -> None:
    targets = [
        # Windows core targets may arrive with a generic server policy category.
        # They must still render in the Windows tab and be selectable for E01
        # Windows images.
        _target("windows_core_forensic_a", "forensic", "system"),
        _target("windows_core_forensic_b", "forensic", "filesystem"),
        _target("windows_core_forensic_c", "forensic", "system"),
        _target("windows_pc_app_policy", "windows", "pc_apps"),
        _target("windows_pc_messenger_policy", "windows", "pc_messenger"),
        _target("android_policy", "android", "basic"),
        _target("ios_policy", "ios", "core"),
        _target("linux_policy", "linux", "system"),
        _target("macos_policy", "macos", "system"),
        _target("ai_activity_policy", "ai_activity", "system"),
    ]
    for registry in (
        ARTIFACT_TYPES,
        ARTIFACT_MFT_FILTERS,
        ANDROID_ARTIFACT_TYPES,
        IOS_ARTIFACT_TYPES,
        LINUX_ARTIFACT_TYPES,
        MACOS_ARTIFACT_TYPES,
    ):
        apply_collection_profile_to_registry(targets, registry)


def main() -> int:
    app_module.create_default_enumerators = lambda: {}
    CollectorWindow.check_server_connection = lambda self: None
    qt_app = QApplication.instance() or QApplication(sys.argv)
    _install_profile()
    window = CollectorWindow(
        {
            "app_name": "unJaena Collector Profile Smoke",
            "version": "smoke",
            "server_url": "https://app.unjaena.com",
            "ws_url": "wss://app.unjaena.com",
        }
    )
    window.device_manager.stop_monitoring()
    window._allow_all_artifacts = True
    window._mapped_allowed_artifacts = set(ARTIFACT_TYPES)
    window._build_artifact_tabs(preserve_index=True)

    expected = {
        "windows_core_forensic_a": "windows",
        "windows_core_forensic_b": "windows",
        "windows_core_forensic_c": "windows",
        "windows_pc_app_policy": "windows",
        "windows_pc_messenger_policy": "windows",
        "android_policy": "android",
        "ios_policy": "ios",
        "linux_policy": "linux",
        "macos_policy": "macos",
        "ai_activity_policy": "ai_activity",
    }
    for artifact_type, category in expected.items():
        assert artifact_type in window.artifact_checks, f"{artifact_type} did not render"
        actual = window._artifact_category(artifact_type)
        assert actual == category, f"{artifact_type} rendered as {actual}, expected {category}"

    window.artifacts_tab.setCurrentIndex(0)
    for cb in window.artifact_checks.values():
        cb.setEnabled(False)
        cb.setChecked(False)
    for artifact_type in expected:
        window.artifact_checks[artifact_type].setEnabled(True)
    window.select_all_cb.setEnabled(True)
    window.select_all_cb.setChecked(True)
    selected = set(window._selected_artifact_types())
    assert {
        "windows_core_forensic_a",
        "windows_core_forensic_b",
        "windows_core_forensic_c",
        "windows_pc_app_policy",
        "windows_pc_messenger_policy",
    } <= selected
    assert "android_policy" not in selected
    assert "ios_policy" not in selected

    window.close()
    print("server_profile_render_smoke_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
