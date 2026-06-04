from contextlib import contextmanager
import shutil
import sqlite3
from pathlib import Path

import pytest

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
