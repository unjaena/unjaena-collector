import json
from pathlib import Path

from collectors.ios_collector import iOSDeviceConnector


def test_mobile_ios_device_backup_yields_summary_file_not_backup_directory(tmp_path: Path):
    connector = iOSDeviceConnector(str(tmp_path), udid="TEST-UDID")
    backup_dir = tmp_path / "ios_backup" / "backup" / "TEST-UDID"
    backup_dir.mkdir(parents=True)
    (backup_dir / "Manifest.plist").write_bytes(b"plist")

    def fake_create_backup(_artifact_dir, _progress_callback=None):
        yield str(backup_dir), {
            "artifact_type": "mobile_ios_device_backup",
            "backup_path": str(backup_dir),
            "status": "success",
            "size_bytes": 5,
        }

    connector.create_backup = fake_create_backup

    results = list(
        connector._collect_device_artifact(
            "mobile_ios_device_backup",
            {},
            tmp_path / "artifact",
        )
    )

    assert len(results) == 1
    file_path, metadata = results[0]
    path = Path(file_path)
    assert path.is_file()
    assert path.name == "ios_device_backup_summary.json"
    assert metadata["backup_directory_uploaded"] is False
    assert metadata["backup_path"] == str(backup_dir)

    summary = json.loads(path.read_text(encoding="utf-8"))
    assert summary["backup_directory_uploaded"] is False
    assert summary["backup_path"] == str(backup_dir)
