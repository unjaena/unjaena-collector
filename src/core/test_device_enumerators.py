from core.device_enumerators import AndroidDeviceEnumerator, iOSDeviceEnumerator
from core.device_manager import DeviceStatus, DeviceType, UnifiedDeviceInfo, UnifiedDeviceManager
from collectors.android_collector import DeviceInfo


class _FakeAndroidMonitor:
    def get_connected_devices(self):
        return [
            DeviceInfo(
                serial="ANDROIDROOT001",
                model="Pixel 9 Pro",
                manufacturer="Google",
                android_version="16",
                sdk_version=36,
                usb_debugging=True,
                security_patch="2026-05-01",
                rooted=True,
                storage_available=128,
            ),
            DeviceInfo(
                serial="ANDROIDUSER002",
                model="Galaxy S25",
                manufacturer="Samsung",
                android_version="16",
                sdk_version=36,
                usb_debugging=True,
                security_patch="2026-05-01",
                rooted=False,
                storage_available=64,
            ),
        ]


class _EmptyAndroidMonitor:
    def get_connected_devices(self):
        return []


def test_android_enumerator_reports_rooted_and_limited_devices():
    enum = AndroidDeviceEnumerator()
    enum._adb_available = True
    enum._monitor = _FakeAndroidMonitor()

    devices = enum.enumerate()

    assert [device.device_type for device in devices] == [DeviceType.ANDROID_DEVICE, DeviceType.ANDROID_DEVICE]
    assert devices[0].metadata["collection_capability"]["collection_model"] == "root_full"
    assert devices[1].metadata["collection_capability"]["collection_model"] == "nonroot_limited"
    assert "Limited collection" in devices[1].selection_disabled_reason


def test_android_enumerator_empty_monitor_is_clean():
    enum = AndroidDeviceEnumerator()
    enum._adb_available = True
    enum._monitor = _EmptyAndroidMonitor()

    assert enum.enumerate() == []


def test_ios_enumerator_reports_paired_and_unpaired_devices(monkeypatch):
    import pymobiledevice3.lockdown as lockdown
    import pymobiledevice3.usbmux as usbmux

    class FakeUSBDevice:
        serial = "IOSPAIRED001"

    class FakeLockdown:
        all_values = {
            "DeviceName": "Case iPhone",
            "ProductType": "iPhone17,2",
            "ProductVersion": "19.0",
            "SerialNumber": "IOS-SERIAL-001",
        }

    monkeypatch.setattr(usbmux, "list_devices", lambda: [FakeUSBDevice()])
    monkeypatch.setattr(lockdown, "create_using_usbmux", lambda serial=None: FakeLockdown())

    enum = iOSDeviceEnumerator()
    enum._available = True
    paired = enum.enumerate()

    assert len(paired) == 1
    assert paired[0].device_type == DeviceType.IOS_DEVICE
    assert paired[0].status == DeviceStatus.READY
    assert paired[0].metadata["ios_version"] == "19.0"

    class LockedUSBDevice:
        serial = "IOSLOCKED002"

    def raise_pairing(serial=None):
        raise RuntimeError("Pairing required")

    monkeypatch.setattr(usbmux, "list_devices", lambda: [LockedUSBDevice()])
    monkeypatch.setattr(lockdown, "create_using_usbmux", raise_pairing)

    locked = enum.enumerate()

    assert len(locked) == 1
    assert locked[0].status == DeviceStatus.LOCKED
    assert locked[0].is_selectable is False
    assert "trust this computer" in locked[0].selection_disabled_reason.lower()


class _FakeFFSEnumerator:
    def register_bundle(self, bundle_path):
        return UnifiedDeviceInfo(
            device_id="mobile_ffs_case_1",
            device_type=DeviceType.MOBILE_FFS_BUNDLE_ANDROID,
            display_name="FFS Bundle (Android) - case.zip",
            status=DeviceStatus.READY,
            metadata={
                "bundle_path": bundle_path,
                "present_artifacts": ["mobile_android_example"],
                "present_artifact_scan_complete": True,
            },
        )


def test_device_manager_refreshes_loaded_mobile_ffs_bundle_metadata():
    manager = UnifiedDeviceManager()
    manager.register_enumerator("mobile_ffs", _FakeFFSEnumerator())
    existing = UnifiedDeviceInfo(
        device_id="mobile_ffs_case_1",
        device_type=DeviceType.MOBILE_FFS_BUNDLE_ANDROID,
        display_name="FFS Bundle (Android) - case.zip",
        status=DeviceStatus.READY,
        metadata={
            "bundle_path": "/tmp/case.zip",
            "present_artifacts": [],
            "present_artifact_scan_complete": True,
        },
        is_selected=True,
    )
    manager._devices[existing.device_id] = existing
    manager._selected_devices.add(existing.device_id)

    assert manager.refresh_mobile_ffs_bundles() == 1

    updated = manager.get_device("mobile_ffs_case_1")
    assert updated.metadata["present_artifacts"] == ["mobile_android_example"]
    assert updated.is_selected is True
    assert manager.get_selected_devices()[0].metadata["present_artifacts"] == ["mobile_android_example"]
