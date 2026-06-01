#!/usr/bin/env python3
"""Device enumeration acceptance checks for the public collector."""
from __future__ import annotations

import os
import sys
from collections import namedtuple
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _usage(total: int, free: int):
    Usage = namedtuple("usage", "total used free")
    return Usage(total=total, used=total - free, free=free)


class _FakeKernel32:
    DRIVE_REMOVABLE = 2
    DRIVE_FIXED = 3
    DRIVE_CDROM = 5

    def GetLogicalDrives(self):
        return (1 << 2) | (1 << 4) | (1 << 5)

    def GetDriveTypeW(self, root):
        drive = str(root)[:1].upper()
        if drive == "C":
            return self.DRIVE_FIXED
        if drive == "E":
            return self.DRIVE_REMOVABLE
        if drive == "F":
            return self.DRIVE_CDROM
        return 0

    def GetVolumeInformationW(
        self,
        root,
        volume_name,
        volume_name_size,
        serial,
        max_component,
        flags,
        fs_name,
        fs_name_size,
    ):
        value = getattr(root, "value", str(root))
        drive = value[:1].upper()
        labels = {"C": "Windows", "E": "EvidenceUSB", "F": "EmptyOptical"}
        filesystems = {"C": "NTFS", "E": "exFAT", "F": "UDF"}
        volume_name.value = labels.get(drive, "")
        fs_name.value = filesystems.get(drive, "")
        serial._obj.value = {"C": 0x12345678, "E": 0x87654321, "F": 0x11111111}.get(drive, 0)
        return 1


def _assert_windows_logical_drive_simulation() -> None:
    import ctypes
    import shutil
    import subprocess
    import core.device_enumerators as de
    from core.device_manager import DeviceType

    old_platform = sys.platform
    old_de_platform = de.sys.platform
    sentinel = object()
    old_windll = getattr(ctypes, "windll", sentinel)
    old_disk_usage = shutil.disk_usage
    had_create_no_window = hasattr(subprocess, "CREATE_NO_WINDOW")
    old_create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", None)

    def fake_disk_usage(root):
        drive = str(root)[:1].upper()
        if drive == "C":
            return _usage(256 * 1024**3, 128 * 1024**3)
        if drive == "E":
            return _usage(32 * 1024**3, 20 * 1024**3)
        raise OSError("empty or inaccessible drive")

    try:
        sys.platform = "win32"
        de.sys.platform = "win32"
        ctypes.windll = SimpleNamespace(kernel32=_FakeKernel32())
        shutil.disk_usage = fake_disk_usage
        if not had_create_no_window:
            subprocess.CREATE_NO_WINDOW = 0

        enum = de.WindowsLogicalDriveEnumerator()
        assert enum.is_available(), "Windows logical drive enumerator is unavailable on simulated win32"
        devices = enum.enumerate()
        ids = {device.device_id: device for device in devices}
        assert "windows_volume_C" in ids, ids
        assert "windows_volume_E" in ids, ids
        assert "windows_volume_F" not in ids, "empty optical drive should not be selectable"

        c_drive = ids["windows_volume_C"]
        e_drive = ids["windows_volume_E"]
        assert c_drive.device_type == DeviceType.WINDOWS_LOGICAL_DRIVE
        assert c_drive.metadata["volume"] == "C"
        assert c_drive.metadata["filesystem"] == "NTFS"
        assert c_drive.metadata["detected_os"] == "windows"
        assert c_drive.is_selectable
        assert e_drive.metadata["is_removable"] is True

        class _UnavailableEnumerator:
            def is_available(self):
                return False

        class _ImageEnumerator:
            def enumerate(self):
                return []

            def supports_realtime(self):
                return False

        patched = {
            "WindowsDiskEnumerator": _UnavailableEnumerator,
            "AndroidDeviceEnumerator": _UnavailableEnumerator,
            "iOSBackupEnumerator": _UnavailableEnumerator,
            "iOSDeviceEnumerator": _UnavailableEnumerator,
            "MobileFFSBundleEnumerator": _UnavailableEnumerator,
            "AndroidHardwareEnumerator": _UnavailableEnumerator,
            "ForensicImageEnumerator": _ImageEnumerator,
        }
        originals = {name: getattr(de, name) for name in patched}
        try:
            for name, replacement in patched.items():
                setattr(de, name, replacement)
            enumerators = de.create_default_enumerators()
        finally:
            for name, original in originals.items():
                setattr(de, name, original)
        assert "windows_volumes" in enumerators, "factory did not register WMI-independent Windows volumes"
    finally:
        sys.platform = old_platform
        de.sys.platform = old_de_platform
        shutil.disk_usage = old_disk_usage
        if had_create_no_window:
            subprocess.CREATE_NO_WINDOW = old_create_no_window
        else:
            try:
                delattr(subprocess, "CREATE_NO_WINDOW")
            except AttributeError:
                pass
        if old_windll is sentinel:
            try:
                delattr(ctypes, "windll")
            except AttributeError:
                pass
        else:
            ctypes.windll = old_windll


def _assert_device_panel_empty_state() -> None:
    from PyQt6.QtWidgets import QApplication
    from core.device_manager import DeviceStatus, DeviceType, UnifiedDeviceInfo, UnifiedDeviceManager
    from gui.device_panel import DeviceListPanel

    app = QApplication.instance() or QApplication(sys.argv)
    manager = UnifiedDeviceManager()
    panel = DeviceListPanel(manager)

    panel._on_scan_started()
    assert "Scanning" in panel.empty_label.text()
    panel._on_scan_completed()
    assert not panel.empty_label.isHidden(), "empty state should be visible when no source exists"
    assert "No local evidence source detected" in panel.empty_label.text()

    device = UnifiedDeviceInfo(
        device_id="windows_volume_C",
        device_type=DeviceType.WINDOWS_LOGICAL_DRIVE,
        display_name="C: Windows (Local drive)",
        status=DeviceStatus.READY,
        size_bytes=256 * 1024**3,
        metadata={
            "volume": "C",
            "drive_type": "Local drive",
            "filesystem": "NTFS",
            "volume_label": "Windows",
            "detected_os": "windows",
        },
        is_selectable=True,
    )
    panel._on_device_added(device)
    assert panel.empty_label.isHidden(), "empty state should hide after a detected source"
    cb = panel.device_checkboxes["windows_volume_C"]
    assert "C:" in cb.text()
    assert "NTFS" in cb.text()
    assert "Windows local filesystem" in cb.toolTip()
    panel.close()
    app.processEvents()


def _assert_actual_local_detection() -> None:
    from core.device_manager import DeviceType
    import core.device_enumerators as de

    if sys.platform == "win32":
        devices = de.WindowsLogicalDriveEnumerator().enumerate()
        assert any(d.device_type == DeviceType.WINDOWS_LOGICAL_DRIVE for d in devices), (
            "no Windows logical drive detected on actual runner"
        )
        return

    if sys.platform.startswith("linux"):
        devices = de.LinuxLocalEnumerator().enumerate()
        assert devices and devices[0].device_type == DeviceType.LINUX_LOCAL_SYSTEM, (
            "Linux local system enumerator did not expose the local filesystem"
        )
        return

    if sys.platform == "darwin":
        devices = de.macOSLocalEnumerator().enumerate()
        assert devices and devices[0].device_type == DeviceType.MACOS_LOCAL_SYSTEM, (
            "macOS local system enumerator did not expose the local filesystem"
        )


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    _assert_windows_logical_drive_simulation()
    _assert_device_panel_empty_state()
    if "--actual-local" in argv:
        _assert_actual_local_detection()
    print("device_enumerator_smoke_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
