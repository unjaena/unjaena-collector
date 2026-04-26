"""Tests for format_detector. Includes synthetic unit tests + an
optional real-corpus integration test against the Hickman Pixel 7a
and iPhone 11 Cellebrite UFED dumps when present on the test host.
"""
from __future__ import annotations

import io
import sys
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parent.parent.parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from collectors.mobile_ffs.format_detector import (
    FormatID,
    HIGH_CONFIDENCE,
    LOW_CONFIDENCE,
    MEDIUM_CONFIDENCE,
    detect_zip_format,
)


def _zip_with_entries(entries: list, *, version_file: bytes = None,
                      log_txt: bytes = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if version_file is not None:
            zf.writestr("version", version_file)
        if log_txt is not None:
            zf.writestr("Log.txt", log_txt)
        for name, payload in entries:
            zf.writestr(name, payload)
    return buf.getvalue()


class FormatDetectorSynthetic(unittest.TestCase):

    def _detect_bytes(self, data: bytes):
        # Write to a temp path because detect_zip_format takes a path
        import tempfile
        tmp = tempfile.NamedTemporaryFile(
            mode="wb", suffix=".zip", delete=False
        )
        tmp.write(data)
        tmp.close()
        try:
            return detect_zip_format(tmp.name)
        finally:
            Path(tmp.name).unlink(missing_ok=True)

    def test_clbx_ios_high_confidence(self):
        data = _zip_with_entries(
            [
                ("metadata1/filesystem.msgpack", b"\x81\xabmount_point\xa1/"),
                ("filesystem1/private/var/mobile/Library/SMS/sms.db", b"x"),
            ],
            version_file=b"CLBX-0.3.1",
        )
        d = self._detect_bytes(data)
        self.assertEqual(d.format_id, FormatID.CELLEBRITE_CLBX_IOS)
        self.assertEqual(d.confidence, HIGH_CONFIDENCE)
        self.assertEqual(d.publisher_version, "CLBX-0.3.1")

    def test_clbx_android_via_heuristic(self):
        # Android Cellebrite zips have no `version` file in the
        # observed corpus — pure layout heuristic.
        data = _zip_with_entries([
            ("Dump/data/data/com.whatsapp/databases/msgstore.db", b"x"),
            ("Dump/system/build.prop", b"y"),
        ])
        d = self._detect_bytes(data)
        self.assertEqual(d.format_id, FormatID.CELLEBRITE_CLBX_ANDROID)
        # No publisher signal -> medium confidence
        self.assertEqual(d.confidence, MEDIUM_CONFIDENCE)

    def test_ufdr_high_confidence(self):
        data = _zip_with_entries([
            ("report.xml", b"<?xml version='1.0'?><Cellebrite/>"),
            ("files/abcd1234.bin", b"hash-renamed-blob"),
        ])
        d = self._detect_bytes(data)
        self.assertEqual(d.format_id, FormatID.CELLEBRITE_UFDR)
        self.assertEqual(d.confidence, HIGH_CONFIDENCE)

    def test_unknown_layout_low_confidence(self):
        data = _zip_with_entries([("random/file.txt", b"x")])
        d = self._detect_bytes(data)
        self.assertEqual(d.format_id, FormatID.GENERIC_ZIP)
        self.assertEqual(d.confidence, LOW_CONFIDENCE)

    def test_log_txt_publisher_software(self):
        # UTF-16 LE BOM + `UFED version: 10.2.0.359`
        log_body = ("UFED Log file\r\n"
                    "UFED version: 10.2.0.359 UFED\r\n").encode("utf-16-le")
        log_body = b"\xff\xfe" + log_body
        data = _zip_with_entries(
            [("filesystem1/private/var/mobile/Library/SMS/sms.db", b"x")],
            version_file=b"CLBX-0.3.1",
            log_txt=log_body,
        )
        d = self._detect_bytes(data)
        self.assertEqual(d.publisher_software, "UFED 10.2.0.359 UFED")

    def test_corrupt_zip_returns_unknown(self):
        d = self._detect_bytes(b"not a real zip")
        self.assertEqual(d.format_id, FormatID.UNKNOWN)
        self.assertEqual(d.confidence, LOW_CONFIDENCE)
        self.assertTrue(any("open_failed" in s for s in d.signals_fired))


class FormatDetectorRealCorpus(unittest.TestCase):
    """Optional integration test — only runs if both Hickman zips
    are present on this host."""

    HICKMAN_ANDROID = (
        r"D:\Images\public-corpus\catalog\Android_14_Public_Image"
        r"\UFED Google Pixel 7a 2024_07_28 (001)"
        r"\EXTRACTION_FFS 01\EXTRACTION_FFS.zip"
    )
    HICKMAN_IOS = (
        r"D:\image\hickman_ios17\iOS_17\Cellebrite_Extraction"
        r"\UFED Apple iPhone 11 (N104AP) 2024_07_28 (001)"
        r"\EXTRACTION_FFS 01\EXTRACTION_FFS.zip"
    )

    def test_hickman_android(self):
        if not Path(self.HICKMAN_ANDROID).exists():
            self.skipTest("Hickman Android corpus not present on this host")
        d = detect_zip_format(self.HICKMAN_ANDROID)
        self.assertEqual(d.format_id, FormatID.CELLEBRITE_CLBX_ANDROID)
        # Android observed corpus has no publisher signals so confidence
        # is medium (heuristic-only).
        self.assertIn(d.confidence, (MEDIUM_CONFIDENCE, HIGH_CONFIDENCE))

    def test_hickman_ios(self):
        if not Path(self.HICKMAN_IOS).exists():
            self.skipTest("Hickman iOS corpus not present on this host")
        d = detect_zip_format(self.HICKMAN_IOS)
        self.assertEqual(d.format_id, FormatID.CELLEBRITE_CLBX_IOS)
        self.assertEqual(d.confidence, HIGH_CONFIDENCE)
        self.assertEqual(d.publisher_version, "CLBX-0.3.1")
        # UFED version recorded from Log.txt
        self.assertIsNotNone(d.publisher_software)
        self.assertIn("UFED", d.publisher_software)


if __name__ == "__main__":
    unittest.main(verbosity=2)
