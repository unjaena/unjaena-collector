"""Tests for cellebrite_adapter — synthetic + real-corpus end-to-end.

Real-corpus tests skipped if D:\\Images Hickman zips are not present.
"""
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
    CASE_MANIFEST_JSON,
    NOT_EXTRACTED_JSONL,
    CaseManifestWriter,
)
from collectors.mobile_ffs.cellebrite_adapter import (
    CellebriteAdapter,
    ResolvedArtifact,
)
from collectors.mobile_ffs.format_detector import FormatID
from collectors.mobile_ffs.path_specs import (
    AndroidArtifactSpec,
    ContainerKind,
    all_artifact_types,
    find_android_spec_by_path,
    find_ios_system_spec_by_path,
)


def _build_android_zip(extra_entries=None) -> bytes:
    """Build a minimal Android Cellebrite-shaped zip for testing."""
    extra_entries = extra_entries or []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # WhatsApp DB at the canonical path for our spec
        zf.writestr(
            "Dump/data/data/com.whatsapp/databases/msgstore.db",
            b"SQLite format 3\x00" + b"\x00" * 1024,
        )
        zf.writestr("Dump/system/build.prop", b"ro.product.brand=Test\n")
        for name, payload in extra_entries:
            zf.writestr(name, payload)
    return buf.getvalue()


class PathSpecsBasic(unittest.TestCase):
    def test_android_spec_match(self):
        spec = find_android_spec_by_path(
            "Dump/data/data/com.whatsapp/databases/msgstore.db"
        )
        self.assertIsNotNone(spec)
        self.assertEqual(spec.artifact_type, "mobile_android_whatsapp")

    def test_android_spec_no_match(self):
        self.assertIsNone(
            find_android_spec_by_path("Dump/data/data/random.app/cache.bin")
        )

    def test_ios_system_spec_match(self):
        spec = find_ios_system_spec_by_path(
            "filesystem1/private/var/mobile/Library/SMS/sms.db"
        )
        self.assertIsNotNone(spec)
        self.assertEqual(spec.artifact_type, "mobile_ios_sms")

    def test_artifact_types_unique_and_namespaced(self):
        types = all_artifact_types()
        self.assertEqual(len(types), len(set(types)),
                         "artifact_type values must be unique")
        for t in types:
            self.assertTrue(
                t.startswith("mobile_android_") or t.startswith("mobile_ios_"),
                f"artifact_type {t!r} must use the mobile_* namespace"
            )


class CellebriteAdapterAndroidSynthetic(unittest.TestCase):

    def test_iter_known_artifacts_finds_whatsapp(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "android.zip"
            zip_path.write_bytes(_build_android_zip())
            with CellebriteAdapter(zip_path) as ad:
                self.assertEqual(ad.format_id,
                                 FormatID.CELLEBRITE_CLBX_ANDROID)
                resolved = list(ad.iter_known_artifacts())
                # All Android specs are reported
                self.assertGreater(len(resolved), 5)
                wa = [r for r in resolved
                      if r.artifact_type == "mobile_android_whatsapp"]
                self.assertEqual(len(wa), 1)
                self.assertTrue(wa[0].present)
                self.assertEqual(
                    wa[0].actual_zip_path,
                    "Dump/data/data/com.whatsapp/databases/msgstore.db",
                )

    def test_extract_to_manifest_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            zip_path = tmp_p / "android.zip"
            zip_path.write_bytes(_build_android_zip())
            case_dir = tmp_p / "case"
            extract_dir = tmp_p / "extracted"
            with CellebriteAdapter(zip_path) as ad, \
                 CaseManifestWriter(
                     case_dir,
                     case_id="test-android",
                     collector_version="0.0.0-test",
                     source_container_path=zip_path,
                 ) as w:
                counts = ad.extract_to_manifest(extract_dir, manifest=w)
            self.assertEqual(counts["extracted"], 1)  # whatsapp
            self.assertGreater(counts["absent"], 5)   # rest absent

            artifacts = [
                json.loads(l)
                for l in (case_dir / ARTIFACTS_JSONL).read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(
                artifacts[0]["artifact_type"], "mobile_android_whatsapp"
            )

            not_ext = [
                json.loads(l)
                for l in (case_dir / NOT_EXTRACTED_JSONL).read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            # Every absent spec is recorded with reason `expected_but_absent:`
            absent_reasons = [r["reason"] for r in not_ext
                              if r["reason"].startswith("expected_but_absent:")]
            self.assertGreater(len(absent_reasons), 5)


class CellebriteAdapterRealCorpus(unittest.TestCase):
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

    def test_hickman_android_artifacts(self):
        if not Path(self.HICKMAN_ANDROID).exists():
            self.skipTest("Hickman Android corpus not present")
        with CellebriteAdapter(self.HICKMAN_ANDROID) as ad:
            resolved = list(ad.iter_known_artifacts())
            present = [r for r in resolved if r.present]
            artifact_types = {r.artifact_type for r in present}
            # Pixel 7a should at minimum have system telephony +
            # whatsapp + telegram + line + viber (corpus verified).
            self.assertIn("mobile_android_whatsapp", artifact_types)
            self.assertIn("mobile_android_telegram", artifact_types)
            self.assertIn("mobile_android_line", artifact_types)
            self.assertIn("mobile_android_viber", artifact_types)

    def test_hickman_ios_artifacts(self):
        if not Path(self.HICKMAN_IOS).exists():
            self.skipTest("Hickman iOS corpus not present")
        with CellebriteAdapter(self.HICKMAN_IOS) as ad:
            self.assertEqual(ad.format_id, FormatID.CELLEBRITE_CLBX_IOS)
            uuid_summary = ad.uuid_map.summary_counts()
            # iPhone 11 has dozens of installed apps
            self.assertGreater(uuid_summary["data_resolved"], 5)
            resolved = list(ad.iter_known_artifacts())
            present = [r for r in resolved if r.present]
            artifact_types = {r.artifact_type for r in present}
            # Core iOS system DBs should be present
            self.assertIn("mobile_ios_sms", artifact_types)
            self.assertIn("mobile_ios_call", artifact_types)
            self.assertIn("mobile_ios_contacts", artifact_types)

    def test_hickman_ios_full_pipeline(self):
        if not Path(self.HICKMAN_IOS).exists():
            self.skipTest("Hickman iOS corpus not present")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            with CellebriteAdapter(self.HICKMAN_IOS) as ad, \
                 CaseManifestWriter(
                     tmp_p / "case",
                     case_id="hickman-ios-pipeline",
                     collector_version="0.0.0-test",
                     source_container_path=Path(self.HICKMAN_IOS),
                 ) as w:
                counts = ad.extract_to_manifest(
                    tmp_p / "extracted", manifest=w,
                )
            self.assertGreater(counts["extracted"], 2,
                               "expected several iOS system DBs to extract")
            manifest = json.loads(
                (tmp_p / "case" / CASE_MANIFEST_JSON).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["detected_format"],
                             "cellebrite_clbx_ios")
            self.assertEqual(manifest["publisher_version"], "CLBX-0.3.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
