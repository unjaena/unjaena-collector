"""Tests for case_manifest.py — synthetic + real-corpus end-to-end."""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parent.parent.parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from collectors.mobile_ffs.case_manifest import (
    ARTIFACTS_JSONL,
    BINARY_BLOBS_JSONL,
    CAPABILITIES_MD,
    CASE_MANIFEST_JSON,
    BlobReason,
    CaseManifestWriter,
    NOT_EXTRACTED_JSONL,
)
from collectors.mobile_ffs.format_detector import detect_zip_format
from collectors.mobile_ffs.safe_zip import (
    inventory_all,
    safe_iter_entries,
)


def _build_zip(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries:
            zf.writestr(name, payload)
    return buf.getvalue()


class CaseManifestSynthetic(unittest.TestCase):

    def test_full_bundle_round_trip(self):
        """End-to-end: detect → extract → manifest → verify all six
        bundle files contain the expected data."""
        # Synthetic Cellebrite Android FFS
        zip_bytes = _build_zip([
            ("Dump/data/data/com.example.app/databases/x.db",
             b"SQLite format 3\x00" + b"\x00" * 1024),
            ("Dump/data/data/com.example.other/cache.bin", b"cached"),
            ("Dump/system/build.prop", b"ro.product.brand=Test\n"),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_path = tmp_path / "source.zip"
            zip_path.write_bytes(zip_bytes)
            case_dir = tmp_path / "case_bundle"

            # 1. Detect format
            det = detect_zip_format(zip_path)

            # 2. Run extraction + inventory under manifest writer
            with CaseManifestWriter(
                case_dir,
                case_id="test-case-001",
                collector_version="0.0.0-test",
                source_container_path=zip_path,
            ) as w:
                w.set_detection(det)
                wanted = lambda i: i.filename.endswith(".db")
                with zipfile.ZipFile(zip_path) as zf:
                    for entry in safe_iter_entries(
                        zf, tmp_path / "extract", select=wanted
                    ):
                        w.append_artifact(
                            entry,
                            artifact_type="mobile_android_app_database_test",
                        )
                    for inv in inventory_all(zf, select_predicate=wanted):
                        w.append_not_extracted(inv)

            # 3. Verify bundle contents
            self.assertTrue((case_dir / ARTIFACTS_JSONL).exists())
            self.assertTrue((case_dir / NOT_EXTRACTED_JSONL).exists())
            self.assertTrue((case_dir / BINARY_BLOBS_JSONL).exists())
            self.assertTrue((case_dir / CASE_MANIFEST_JSON).exists())
            self.assertTrue((case_dir / CAPABILITIES_MD).exists())

            artifacts = [json.loads(l) for l in
                         (case_dir / ARTIFACTS_JSONL).read_text(
                             encoding="utf-8"
                         ).splitlines()]
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0]["artifact_type"],
                             "mobile_android_app_database_test")
            self.assertEqual(len(artifacts[0]["source_sha256"]), 64)

            not_extracted = [
                json.loads(l) for l in
                (case_dir / NOT_EXTRACTED_JSONL).read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            # 2 non-.db entries should be recorded as not_extracted
            paths = {r["zip_entry_path"] for r in not_extracted}
            self.assertIn("Dump/data/data/com.example.other/cache.bin", paths)
            self.assertIn("Dump/system/build.prop", paths)

            manifest = json.loads(
                (case_dir / CASE_MANIFEST_JSON).read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["case_id"], "test-case-001")
            self.assertEqual(manifest["artifacts_count"], 1)
            self.assertEqual(manifest["not_extracted_count"], 2)
            self.assertEqual(manifest["detected_format"],
                             "cellebrite_clbx_android")
            # Source SHA-256 binds to outer container
            self.assertEqual(len(manifest["source_container_sha256"]), 64)

            # capabilities.md is human-readable, contains the case ID
            cap = (case_dir / CAPABILITIES_MD).read_text(encoding="utf-8")
            self.assertIn("test-case-001", cap)
            self.assertIn("cellebrite_clbx_android", cap)
            # Neutral binary-blob vocabulary present in the template
            self.assertIn("Opaque containers", cap)

    def test_binary_blob_neutral_vocabulary(self):
        """The collector's BlobReason vocabulary must NOT contain any
        word that names a specific container scheme. This is a
        regression guard for the public-collector security policy.

        The forbidden list is loaded from a sibling resource so this
        test source itself stays free of those tokens.
        """
        forbidden_path = (
            Path(__file__).parent / "_forbidden_blob_tokens.txt"
        )
        self.assertTrue(
            forbidden_path.exists(),
            "_forbidden_blob_tokens.txt resource missing"
        )
        # Hex-encoded in the resource so the file body itself stays
        # grep-clean. Decode at test time only.
        forbidden = set()
        for line in forbidden_path.read_text(
            encoding="utf-8"
        ).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                forbidden.add(bytes.fromhex(line).decode("ascii").lower())
            except (ValueError, UnicodeDecodeError):
                continue
        self.assertGreater(len(forbidden), 5)
        attrs = [v for k, v in vars(BlobReason).items()
                 if not k.startswith("_") and isinstance(v, str)]
        self.assertGreater(len(attrs), 0)
        for value in attrs:
            lower = value.lower()
            for bad in forbidden:
                self.assertNotIn(bad, lower,
                                 f"BlobReason value {value!r} contains "
                                 f"forbidden token")


class CaseManifestRealCorpus(unittest.TestCase):
    """End-to-end against the real Hickman iOS 17 corpus."""

    HICKMAN_IOS = (
        r"D:\image\hickman_ios17\iOS_17\Cellebrite_Extraction"
        r"\UFED Apple iPhone 11 (N104AP) 2024_07_28 (001)"
        r"\EXTRACTION_FFS 01\EXTRACTION_FFS.zip"
    )

    def test_hickman_ios_bundle(self):
        if not Path(self.HICKMAN_IOS).exists():
            self.skipTest("Hickman iOS corpus not present")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case_dir = tmp_path / "case_bundle"

            zip_path = Path(self.HICKMAN_IOS)
            det = detect_zip_format(zip_path)
            wanted = lambda i: i.filename.endswith("/sms.db")

            with CaseManifestWriter(
                case_dir,
                case_id="hickman-ios17-test",
                collector_version="0.0.0-test",
                source_container_path=zip_path,
            ) as w:
                w.set_detection(det)
                with zipfile.ZipFile(zip_path) as zf:
                    for entry in safe_iter_entries(
                        zf, tmp_path / "extract", select=wanted
                    ):
                        w.append_artifact(
                            entry,
                            artifact_type="mobile_ios_app_database_sms",
                        )

            manifest = json.loads(
                (case_dir / CASE_MANIFEST_JSON).read_text(encoding="utf-8")
            )
            # iOS Cellebrite has known publisher signal
            self.assertEqual(manifest["detected_format"],
                             "cellebrite_clbx_ios")
            self.assertEqual(manifest["publisher_version"], "CLBX-0.3.1")
            # SMS DB exists in the corpus
            self.assertGreaterEqual(manifest["artifacts_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
