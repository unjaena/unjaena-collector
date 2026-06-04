from pathlib import Path
import plistlib

from collectors import ios_collector
from collectors.ios_collector import iOSDeviceConnector


def test_ios_encryption_setup_failure_does_not_fall_back_to_plain_backup(tmp_path: Path, monkeypatch):
    class FakeBackupService:
        will_encrypt = False

    connector = iOSDeviceConnector(str(tmp_path), udid="IOS-UDID-001")
    connector._lockdown = object()
    connector.set_password_callback(lambda marker: "temporary-password")

    monkeypatch.setenv("UNJAENA_IOS_ALLOW_RUNTIME_ENCRYPTION", "1")
    monkeypatch.setattr(ios_collector, "PYMOBILEDEVICE3_AVAILABLE", True)
    monkeypatch.setattr(ios_collector, "Mobilebackup2Service", lambda lockdown: FakeBackupService())
    monkeypatch.setattr(connector, "_get_device_backup_encryption_state", lambda: False)
    monkeypatch.setattr(connector, "_change_password_with_timeout", lambda backup_dir, old_pw, new_pw: False)

    results = list(connector.create_backup(tmp_path))

    assert len(results) == 1
    path, meta = results[0]
    assert path == ""
    assert meta["status"] == "error"
    assert "Failed to enable iOS encrypted backup" in meta["error"]


def test_ios_encryption_setup_cancel_does_not_fall_back_to_plain_backup(tmp_path: Path, monkeypatch):
    class FakeBackupService:
        will_encrypt = False

    connector = iOSDeviceConnector(str(tmp_path), udid="IOS-UDID-001")
    connector._lockdown = object()
    connector.set_password_callback(lambda marker: None)

    monkeypatch.setenv("UNJAENA_IOS_ALLOW_RUNTIME_ENCRYPTION", "1")
    monkeypatch.setattr(ios_collector, "PYMOBILEDEVICE3_AVAILABLE", True)
    monkeypatch.setattr(ios_collector, "Mobilebackup2Service", lambda lockdown: FakeBackupService())
    monkeypatch.setattr(connector, "_get_device_backup_encryption_state", lambda: False)

    results = list(connector.create_backup(tmp_path))

    assert len(results) == 1
    path, meta = results[0]
    assert path == ""
    assert meta["status"] == "error"
    assert meta["error"] == "iOS encrypted backup setup was cancelled."


def test_ios_encryption_state_mismatch_after_enable_fails_without_plain_backup(
    tmp_path: Path,
    monkeypatch,
):
    class FakeBackupService:
        will_encrypt = False

    connector = iOSDeviceConnector(str(tmp_path), udid="IOS-UDID-001")
    connector._lockdown = object()
    connector.set_password_callback(lambda marker: "temporary-password")

    monkeypatch.setenv("UNJAENA_IOS_ALLOW_RUNTIME_ENCRYPTION", "1")
    monkeypatch.setattr(ios_collector, "PYMOBILEDEVICE3_AVAILABLE", True)
    monkeypatch.setattr(ios_collector, "Mobilebackup2Service", lambda lockdown: FakeBackupService())
    monkeypatch.setattr(connector, "_get_device_backup_encryption_state", lambda: False)
    monkeypatch.setattr(connector, "_change_password_with_timeout", lambda backup_dir, old_pw, new_pw: True)
    monkeypatch.setattr(connector, "_verify_device_backup_encryption_state", lambda expected, progress_callback=None: False)

    results = list(connector.create_backup(tmp_path))

    assert len(results) == 1
    path, meta = results[0]
    assert path == ""
    assert meta["status"] == "error"
    assert "Failed to verify that iOS encrypted backup was enabled" in meta["error"]
    assert connector._encryption_action is None
    assert connector._forensic_backup_password is None


def test_ios_encryption_disabled_by_default_requires_pre_enabled_backup(
    tmp_path: Path,
    monkeypatch,
):
    connector = iOSDeviceConnector(str(tmp_path), udid="IOS-UDID-001")
    connector._lockdown = object()
    connector.set_password_callback(lambda marker: "temporary-password")

    monkeypatch.setattr(ios_collector, "PYMOBILEDEVICE3_AVAILABLE", True)
    monkeypatch.setattr(connector, "_get_device_backup_encryption_state", lambda: False)

    results = list(connector.create_backup(tmp_path))

    assert len(results) == 1
    path, meta = results[0]
    assert path == ""
    assert meta["status"] == "error"
    assert "does not enable encrypted backup during collection" in meta["error"]


def test_ios_encrypted_backup_manifest_mismatch_fails_extraction(
    tmp_path: Path,
    monkeypatch,
):
    class FakeBackupService:
        will_encrypt = True

        def backup(self, full, backup_directory, progress_callback=None):
            backup_path = Path(backup_directory) / "IOS-UDID-001"
            backup_path.mkdir(parents=True)
            with (backup_path / "Info.plist").open("wb") as f:
                plistlib.dump(
                    {
                        "Device Name": "iPhone",
                        "Target Identifier": "IOS-UDID-001",
                        "Product Type": "iPhone13,1",
                        "Product Version": "26.5",
                    },
                    f,
                )
            with (backup_path / "Manifest.plist").open("wb") as f:
                plistlib.dump({"IsEncrypted": False}, f)

    connector = iOSDeviceConnector(str(tmp_path), udid="IOS-UDID-001")
    connector._lockdown = object()
    connector._forensic_backup_password = "temporary-password"

    monkeypatch.setattr(ios_collector, "PYMOBILEDEVICE3_AVAILABLE", True)
    monkeypatch.setattr(ios_collector, "Mobilebackup2Service", lambda lockdown: FakeBackupService())
    monkeypatch.setattr(connector, "_get_device_backup_encryption_state", lambda: True)

    results = list(connector.create_backup(tmp_path))

    assert len(results) == 1
    path, meta = results[0]
    assert path == ""
    assert meta["status"] == "error"
    assert "expected to be encrypted" in meta["error"]
