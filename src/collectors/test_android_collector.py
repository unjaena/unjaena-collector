from pathlib import Path
import subprocess

import pytest

from collectors import android_collector
from collectors.android_collector import AndroidCollector, DeviceInfo


class _OneUnauthorizedDeviceMonitor:
    def get_connected_devices(self):
        return [
            DeviceInfo(
                serial="04e8:6860",
                model="Unknown",
                manufacturer="Unknown",
                android_version="Unknown",
                sdk_version=0,
                usb_debugging=False,
                rooted=False,
                vendor_id=0x04E8,
                product_id=0x6860,
            )
        ]


def test_android_connect_reports_missing_adb_access_without_retrying_libusb(tmp_path: Path, monkeypatch):
    collector = AndroidCollector(str(tmp_path))
    collector.monitor = _OneUnauthorizedDeviceMonitor()

    monkeypatch.setattr(android_collector, "USB_AVAILABLE", True)
    monkeypatch.setattr(collector, "_find_system_adb", lambda: None)

    def fail_if_called(serial=None):
        raise AssertionError("unauthorized devices must not retry libusb connect")

    monkeypatch.setattr(collector, "_connect_device_usb", fail_if_called)

    with pytest.raises(RuntimeError) as exc:
        collector.connect()

    assert "ADB shell access is not available" in str(exc.value)


def test_android_connect_reports_system_adb_unauthorized_when_libusb_serial_is_placeholder(
    tmp_path: Path,
    monkeypatch,
):
    collector = AndroidCollector(str(tmp_path))
    collector.monitor = _OneUnauthorizedDeviceMonitor()

    monkeypatch.setattr(android_collector, "USB_AVAILABLE", True)
    monkeypatch.setattr(collector, "_find_system_adb", lambda: r"C:\adb\adb.exe")

    def fake_run(cmd, *args, **kwargs):
        assert cmd[:2] == [r"C:\adb\adb.exe", "devices"]
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=b"List of devices attached\n5200f670421bb56d\tunauthorized\n",
            stderr=b"",
        )

    monkeypatch.setattr(android_collector.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError) as exc:
        collector.connect()

    assert "5200f670421bb56d is unauthorized" in str(exc.value)
    assert collector.device_serial == "5200f670421bb56d"
