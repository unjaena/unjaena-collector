from core.device_enumerators import ForensicImageEnumerator
from core.device_manager import DeviceType


def test_forensic_image_enumerator_registers_e01(tmp_path, monkeypatch):
    image = tmp_path / "evidence.E01"
    segment = tmp_path / "evidence.E02"
    image.write_bytes(b"EVF\t\r\n\xff\x00")
    segment.write_bytes(b"segment")

    monkeypatch.setattr(
        ForensicImageEnumerator,
        "_get_e01_disk_size",
        lambda self, path: 4096,
    )
    monkeypatch.setattr(
        ForensicImageEnumerator,
        "_detect_image_os",
        lambda self, path, device_type: ("windows", "NTFS"),
    )

    enumerator = ForensicImageEnumerator()
    device = enumerator.register_image(str(image))

    assert device.device_type == DeviceType.E01_IMAGE
    assert device.display_name == "evidence.E01"
    assert device.size_bytes == 4096
    assert device.metadata["extension"] == ".e01"
    assert device.metadata["detected_os"] == "windows"
    assert device.metadata["filesystem_type"] == "NTFS"
    assert device.metadata["segments"] == [str(image.resolve()), str(segment.resolve())]


def test_forensic_image_enumerator_marks_dmg_as_image(tmp_path, monkeypatch):
    image = tmp_path / "macos.dmg"
    image.write_bytes(b"koly")

    monkeypatch.setattr(
        ForensicImageEnumerator,
        "_detect_image_os",
        lambda self, path, device_type: ("macos", "HFS+"),
    )

    enumerator = ForensicImageEnumerator()
    device = enumerator.register_image(str(image))

    assert device.device_type == DeviceType.DMG_IMAGE
    assert device.is_image


def test_forensic_image_enumerator_registers_split_raw(tmp_path, monkeypatch):
    first = tmp_path / "evidence.001"
    second = tmp_path / "evidence.002"
    first.write_bytes(b"a" * 10)
    second.write_bytes(b"b" * 20)

    monkeypatch.setattr(
        ForensicImageEnumerator,
        "_detect_image_os",
        lambda self, path, device_type: ("windows", "NTFS"),
    )

    enumerator = ForensicImageEnumerator()
    device = enumerator.register_image(str(first))

    assert device.device_type == DeviceType.RAW_IMAGE
    assert device.display_name == "evidence.001"
    assert device.size_bytes == 30
    assert device.metadata["extension"] == ".001"
    assert device.metadata["segments"] == [str(first.resolve()), str(second.resolve())]


def test_forensic_image_enumerator_accepts_supported_volume_images(tmp_path, monkeypatch):
    image = tmp_path / "volume.ext4"
    image.write_bytes(b"\x00" * 4096)

    monkeypatch.setattr(
        ForensicImageEnumerator,
        "_detect_image_os",
        lambda self, path, device_type: ("linux", "ext4"),
    )

    enumerator = ForensicImageEnumerator()
    device = enumerator.register_image(str(image))

    assert device.device_type == DeviceType.RAW_IMAGE
    assert device.is_image
    assert device.metadata["extension"] == ".ext4"


def test_forensic_image_enumerator_rejects_unimplemented_source_formats(tmp_path):
    image = tmp_path / "disc.iso"
    image.write_bytes(b"\x00" * 4096)

    enumerator = ForensicImageEnumerator()

    try:
        enumerator.register_image(str(image))
    except ValueError as exc:
        assert "Unsupported file type" in str(exc)
    else:
        raise AssertionError("ISO must not be accepted until an ISO/UDF backend is implemented")


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
