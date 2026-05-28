import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from unjaena_collector import device_discovery
from unjaena_collector.device_discovery import DeviceInfo
from unjaena_collector.gui import _safe_text
from unjaena_collector.source_formats import candidate_artifacts_for_path


class GuiTests(unittest.TestCase):
    def test_safe_text_removes_line_breaks_and_limits_length(self):
        text = _safe_text("a\nb" + "c" * 200, 12)
        self.assertNotIn("\n", text)
        self.assertLessEqual(len(text), 12)
        self.assertTrue(text.endswith("..."))

    def test_mobile_bundle_extensions_map_to_source_artifact(self):
        self.assertIn("mobile_ffs_bundle", candidate_artifacts_for_path(Path("case.ufdr")))
        self.assertIn("mobile_ffs_bundle", candidate_artifacts_for_path(Path("case.clbx")))

    def test_device_size_label_formats_bytes(self):
        device = DeviceInfo(device_id="d", kind="local", label="Local", size_bytes=5 * 1024 * 1024)
        self.assertEqual(device.size_label, "5.0 MB")


class DeviceDiscoveryTests(unittest.TestCase):
    def test_discover_devices_keeps_local_device_when_probe_fails(self):
        with patch.object(device_discovery, "_ios_usb_devices", side_effect=RuntimeError("broken usbmux")):
            devices, diagnostics = device_discovery.discover_devices()
        self.assertTrue(any(device.device_id == "local_system" for device in devices))
        self.assertTrue(any("iOS USB: scan failed" in item for item in diagnostics))

    def test_ios_usb_devices_accepts_async_pymobiledevice3_api(self):
        usbmux = types.ModuleType("pymobiledevice3.usbmux")
        lockdown_mod = types.ModuleType("pymobiledevice3.lockdown")

        class UsbDevice:
            serial = "00008110001234567890ABCD"

        class Lockdown:
            async def all_values(self):
                return {"DeviceName": "Case iPhone", "ProductType": "iPhone16,2", "ProductVersion": "18.5"}

        async def list_devices():
            return [UsbDevice()]

        async def create_using_usbmux(serial):
            self.assertEqual(serial, UsbDevice.serial)
            return Lockdown()

        usbmux.list_devices = list_devices
        lockdown_mod.create_using_usbmux = create_using_usbmux

        with patch.dict(sys.modules, {
            "pymobiledevice3": types.ModuleType("pymobiledevice3"),
            "pymobiledevice3.usbmux": usbmux,
            "pymobiledevice3.lockdown": lockdown_mod,
        }):
            devices, diagnostic = device_discovery._ios_usb_devices()

        self.assertEqual(diagnostic, "iOS USB: ready.")
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].kind, "ios_usb")
        self.assertIn("Case iPhone", devices[0].label)

    def test_ios_usb_devices_accepts_async_iterable_device_list(self):
        usbmux = types.ModuleType("pymobiledevice3.usbmux")
        lockdown_mod = types.ModuleType("pymobiledevice3.lockdown")

        class UsbDevice:
            serial = "async-generator-device"

        class Lockdown:
            all_values = {"DeviceName": "Lab iPad", "ProductType": "iPad14,3", "ProductVersion": "17.7"}

        async def gen_devices():
            yield UsbDevice()

        def list_devices():
            return gen_devices()

        def create_using_usbmux(serial):
            return Lockdown()

        usbmux.list_devices = list_devices
        lockdown_mod.create_using_usbmux = create_using_usbmux

        with patch.dict(sys.modules, {
            "pymobiledevice3": types.ModuleType("pymobiledevice3"),
            "pymobiledevice3.usbmux": usbmux,
            "pymobiledevice3.lockdown": lockdown_mod,
        }):
            devices, diagnostic = device_discovery._ios_usb_devices()

        self.assertEqual(diagnostic, "iOS USB: ready.")
        self.assertEqual(devices[0].label, "iOS USB - Lab iPad")

    def test_android_adb_states_are_reported_without_crashing(self):
        output = "List of devices attached\nSERIAL123 device product:pixel model:Pixel_8 device:akita\nLOCKED456 unauthorized\n"
        completed = subprocess.CompletedProcess(["adb"], 0, stdout=output, stderr="")
        with patch.object(device_discovery.shutil, "which", return_value="/usr/bin/adb"), \
             patch.object(device_discovery, "_run", return_value=completed):
            devices, diagnostic = device_discovery._adb_devices()
        self.assertEqual(diagnostic, "Android USB: ready.")
        self.assertEqual([device.status for device in devices], ["ready", "locked"])
        self.assertIn("Pixel 8", devices[0].label)

    def test_mounted_volume_probe_reports_external_filesystems(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            volume = root / "USB_EVIDENCE"
            volume.mkdir()
            with patch.object(device_discovery, "_mounted_volume_roots", return_value=[root]):
                devices, diagnostic = device_discovery._mounted_volumes()
        self.assertEqual(diagnostic, "Mounted volumes: ready.")
        self.assertTrue(any(device.kind == "mounted_volume" and "USB_EVIDENCE" in device.label for device in devices))

    def test_linux_block_device_probe_parses_usb_disk(self):
        payload = '{"blockdevices":[{"name":"sdb","type":"disk","size":1048576,"model":"USB Drive","tran":"usb","rm":true,"mountpoint":null,"label":null}]}'
        completed = subprocess.CompletedProcess(["lsblk"], 0, stdout=payload, stderr="")
        with patch.object(device_discovery.sys, "platform", "linux"), \
             patch.object(device_discovery.shutil, "which", return_value="/usr/bin/lsblk"), \
             patch.object(device_discovery, "_run", return_value=completed):
            devices, diagnostic = device_discovery._linux_block_devices()
        self.assertEqual(diagnostic, "Linux block devices: ready.")
        self.assertEqual(devices[0].kind, "linux_block_device")
        self.assertIn("USB block device", devices[0].label)
        self.assertFalse(devices[0].selectable)

    def test_macos_disk_probe_parses_diskutil_plist(self):
        import plistlib

        payload = plistlib.dumps({"AllDisksAndPartitions": [{"DeviceIdentifier": "disk2", "Content": "GUID_partition_scheme", "Size": 2048}]})
        completed = subprocess.CompletedProcess(["diskutil"], 0, stdout=payload.decode("utf-8"), stderr="")
        with patch.object(device_discovery.sys, "platform", "darwin"), \
             patch.object(device_discovery.shutil, "which", return_value="/usr/sbin/diskutil"), \
             patch.object(device_discovery, "_run", return_value=completed):
            devices, diagnostic = device_discovery._macos_physical_disks()
        self.assertEqual(diagnostic, "macOS disks: ready.")
        self.assertEqual(devices[0].kind, "macos_disk")
        self.assertEqual(devices[0].metadata["path"], "/dev/rdisk2")


class UpdaterTests(unittest.TestCase):
    def test_update_parser_selects_windows_exe(self):
        from unjaena_collector import updater

        assets = [
            {"name": "SHA256SUMS.txt", "browser_download_url": "https://example.invalid/sums", "size": 10},
            {"name": "unjaena-collector-desktop-0.3.3-windows-amd64.exe", "browser_download_url": "https://example.invalid/app.exe", "size": 123},
        ]
        asset = updater.select_asset(assets, system="Windows", machine="AMD64")
        self.assertIsNotNone(asset)
        self.assertTrue(asset.name.endswith("windows-amd64.exe"))

    def test_update_info_compares_versions(self):
        from unjaena_collector import updater

        info = updater.parse_release({"tag_name": "unjaena-collector-v0.3.4", "assets": []}, current_version="0.3.3")
        self.assertTrue(info.available)
        current = updater.parse_release({"tag_name": "unjaena-collector-v0.3.3", "assets": []}, current_version="0.3.3")
        self.assertFalse(current.available)


class PrivilegeTests(unittest.TestCase):
    def test_privilege_status_shape_is_stable(self):
        from unjaena_collector.privileges import privilege_status

        status = privilege_status()
        self.assertIsInstance(status.elevated, bool)
        self.assertTrue(status.platform)
        self.assertTrue(status.detail)


if __name__ == "__main__":
    unittest.main()
