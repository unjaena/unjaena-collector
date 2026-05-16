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
