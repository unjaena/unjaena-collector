import unittest
from pathlib import Path

from unjaena_collector.device_discovery import DeviceInfo
from unjaena_collector.gui import _safe_text
from unjaena_collector.source_formats import candidate_artifacts_for_path


class GuiTests(unittest.TestCase):
    def test_safe_text_removes_line_breaks_and_limits_length(self):
        text = _safe_text("a\nb" + "c" * 200, 12)
        self.assertNotIn("\n", text)
        self.assertLessEqual(len(text), 12)
        self.assertTrue(text.endswith("..."))

    def test_mobile_bundle_extensions_map_to_source_artifact(self):
        self.assertIn("mobile_ffs_bundle", candidate_artifacts_for_path(Path("case.ufdr")))
        self.assertIn("mobile_ffs_bundle", candidate_artifacts_for_path(Path("case.clbx")))

    def test_device_size_label_formats_bytes(self):
        device = DeviceInfo(device_id="d", kind="local", label="Local", size_bytes=5 * 1024 * 1024)
        self.assertEqual(device.size_label, "5.0 MB")


if __name__ == "__main__":
    unittest.main()
