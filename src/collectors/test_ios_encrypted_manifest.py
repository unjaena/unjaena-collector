from contextlib import contextmanager
from datetime import datetime
from types import SimpleNamespace
import shutil
import sqlite3
from pathlib import Path

import pytest

from collectors import ios_collector
from collectors import ios_backup_decryptor
from collectors.ios_backup_decryptor import iOSEncryptedBackupParser


def _write_manifest(path: Path, rows=None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            "CREATE TABLE Files ("
            "fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)"
        )
        for row in rows or []:
            conn.execute(
                "INSERT INTO Files (fileID, domain, relativePath, flags) "
                "VALUES (?, ?, ?, ?)",
                row,
            )
        conn.commit()
    finally:
        conn.close()
    return path


class _CursorBackup:
    def __init__(self, *, count=None, exc=None):
        self.count = count
        self.exc = exc

    @contextmanager
    def manifest_db_cursor(self):
        if self.exc:
            raise self.exc

        class Cursor:
            def execute(self, _sql):
                return None

            def fetchone(self):
                return (self_count,)

        self_count = self.count
        yield Cursor()


def test_create_encrypted_backup_rejects_unreadable_manifest(tmp_path, monkeypatch):
    class FakeEncryptedBackup:
        def __init__(self, *, backup_directory, passphrase):
            self._cursor_backup = _CursorBackup(exc=RuntimeError("bad password"))

        def manifest_db_cursor(self):
            return self._cursor_backup.manifest_db_cursor()

    monkeypatch.setattr(ios_backup_decryptor, "IPHONE_BACKUP_DECRYPT_AVAILABLE", True)
    monkeypatch.setattr(ios_backup_decryptor, "EncryptedBackup", FakeEncryptedBackup)

    backup, error = ios_backup_decryptor.create_encrypted_backup(str(tmp_path), "pw")

    assert backup is None
    assert "Unable to decrypt iOS backup manifest" in error


def test_create_encrypted_backup_accepts_readable_manifest(tmp_path, monkeypatch):
    class FakeEncryptedBackup:
        def __init__(self, *, backup_directory, passphrase):
            self._cursor_backup = _CursorBackup(count=3)

        def manifest_db_cursor(self):
            return self._cursor_backup.manifest_db_cursor()

    monkeypatch.setattr(ios_backup_decryptor, "IPHONE_BACKUP_DECRYPT_AVAILABLE", True)
    monkeypatch.setattr(ios_backup_decryptor, "EncryptedBackup", FakeEncryptedBackup)

    backup, error = ios_backup_decryptor.create_encrypted_backup(str(tmp_path), "pw")

    assert backup is not None
    assert error == ""


def test_encrypted_parser_requires_nonempty_manifest(tmp_path):
    class EmptyManifestBackup:
        def save_manifest_file(self, output_filename):
            _write_manifest(Path(output_filename))

    with pytest.raises(RuntimeError, match="contains no files"):
        iOSEncryptedBackupParser(tmp_path, EmptyManifestBackup())


def test_encrypted_parser_lists_manifest_globs(tmp_path):
    manifest = _write_manifest(
        tmp_path / "source" / "Manifest.db",
        rows=[
            (
                "a" * 40,
                "AppDomain-com.example.chat",
                "Library/Application Support/main.sqlite",
                1,
            ),
            (
                "b" * 40,
                "HomeDomain",
                "Library/SMS/sms.db",
                1,
            ),
        ],
    )

    class ManifestBackup:
        def save_manifest_file(self, output_filename):
            shutil.copy2(manifest, output_filename)

    parser = iOSEncryptedBackupParser(tmp_path, ManifestBackup())
    try:
        app_files = list(
            parser.list_files(
                domain_filter="AppDomain-com.example.*",
                path_pattern="Library/*/*.sqlite",
            )
        )
        sms_files = list(
            parser.list_files(
                domain_filter="HomeDomain",
                path_pattern="Library/SMS/sms.db",
            )
        )
    finally:
        parser.close()

    assert [item["relative_path"] for item in app_files] == [
        "Library/Application Support/main.sqlite"
    ]
    assert [item["relative_path"] for item in sms_files] == [
        "Library/SMS/sms.db"
    ]


def test_ios_collector_collects_server_manifest_targets(tmp_path, monkeypatch):
    class FakeParser:
        def __init__(self, root: Path):
            self.exact_payload = root / "exact-source.db"
            self.pattern_payload = root / "pattern-source.db"
            self.exact_payload.write_bytes(b"exact")
            self.pattern_payload.write_bytes(b"pattern")

        def extract_file(self, domain, relative_path, output_path):
            if domain == "HomeDomain" and relative_path == "Library/Data/example.db":
                shutil.copy2(self.exact_payload, output_path)
                return True
            return False

        def list_files(self, domain_filter=None, path_pattern=None):
            if (
                domain_filter == "AppDomain-com.example.app"
                and path_pattern == "Documents/*"
            ):
                yield {
                    "domain": "AppDomain-com.example.app",
                    "relative_path": "Documents/cache/example.db",
                    "backup_path": str(self.pattern_payload),
                }

    collector = ios_collector.iOSCollector(str(tmp_path / "out"))
    collector.backup_info = SimpleNamespace(
        encrypted=False,
        device_name="Device",
        device_id="UDID",
        ios_version="1.0",
        backup_date=datetime(2026, 1, 1),
    )
    collector.parser = FakeParser(tmp_path)

    monkeypatch.setitem(
        ios_collector.IOS_ARTIFACT_TYPES,
        "mobile_ios_example",
        {
            "manifest_targets": [
                {
                    "manifest_domain": "HomeDomain",
                    "manifest_path": "Library/Data/example.db",
                },
                {
                    "manifest_domain": "AppDomain-com.example.app",
                    "manifest_path": "Documents/*",
                    "pattern": True,
                },
            ],
        },
    )

    results = [
        (Path(path).name, metadata["domain"])
        for path, metadata in collector.collect("mobile_ios_example")
        if path
    ]

    assert results == [
        ("example.db", "HomeDomain"),
        ("8742d779b350_example.db", "AppDomain-com.example.app"),
    ]
