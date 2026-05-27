import unittest

from unjaena_collector.gui import _safe_text


class GuiTests(unittest.TestCase):
    def test_safe_text_removes_line_breaks_and_limits_length(self):
        text = _safe_text("a\nb" + "c" * 200, 12)
        self.assertNotIn("\n", text)
        self.assertLessEqual(len(text), 12)
        self.assertTrue(text.endswith("..."))


if __name__ == "__main__":
    unittest.main()
