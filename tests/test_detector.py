import os
import random
import tempfile
import unittest

from demo_files import make_docx, make_png, paragraph
from detector import (
    ActivityTracker,
    Indicator,
    analyze_file,
    calculate_entropy,
    is_ransom_note,
    severity_for,
    strip_suspicious_extension,
    total_score,
)


def names(indicators):
    return {indicator.name for indicator in indicators}


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.rng = random.Random(1)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, data):
        path = os.path.join(self.temp.name, name)
        with open(path, "wb") as file:
            file.write(data)
        return path

    def test_entropy_range(self):
        self.assertEqual(calculate_entropy(b""), 0.0)
        self.assertEqual(calculate_entropy(b"a" * 1000), 0.0)
        self.assertGreater(calculate_entropy(os.urandom(4096)), 7.9)
        text = paragraph(self.rng, 40).encode()
        self.assertLess(calculate_entropy(text), 5.0)

    def test_clean_text_has_no_indicators(self):
        path = self.write("notes.txt", paragraph(self.rng, 40).encode())
        indicators, entropy = analyze_file(path)
        self.assertEqual(indicators, [])
        self.assertLess(entropy, 5.0)

    def test_non_english_text_is_clean(self):
        path = self.write("notes.txt", ("આજની મીટિંગ નોંધ " * 200).encode("utf-8"))
        self.assertEqual(analyze_file(path)[0], [])

    def test_encrypted_text_file_in_place(self):
        path = self.write("notes.txt", os.urandom(4096))
        indicators, _ = analyze_file(path, baseline_entropy=4.2)
        self.assertEqual(names(indicators), {"entropy_jump", "text_corrupted"})
        self.assertEqual(severity_for(total_score(indicators)), "CRITICAL")

    def test_encrypted_copy_with_locked_extension(self):
        path = self.write("report.txt.locked", os.urandom(4096))
        indicators, _ = analyze_file(path)
        self.assertEqual(names(indicators), {"suspicious_extension", "high_entropy"})

    def test_compressed_formats_are_not_flagged(self):
        png = self.write("photo.png", make_png(self.rng))
        docx = os.path.join(self.temp.name, "contract.docx")
        make_docx(docx, paragraph(self.rng, 40))
        self.assertEqual(analyze_file(png)[0], [])
        self.assertEqual(analyze_file(docx)[0], [])

    def test_broken_header_is_flagged(self):
        path = self.write("photo.png", os.urandom(4096))
        self.assertIn("header_mismatch", names(analyze_file(path)[0]))

    def test_small_random_file_skips_entropy(self):
        path = self.write("tiny.bin", os.urandom(100))
        indicators, entropy = analyze_file(path)
        self.assertIsNone(entropy)
        self.assertEqual(indicators, [])

    def test_ransom_note_names(self):
        self.assertTrue(is_ransom_note("HOW_TO_DECRYPT_FILES.txt"))
        self.assertTrue(is_ransom_note("Restore-Files.html"))
        self.assertFalse(is_ransom_note("decrypt_notes.py"))
        self.assertFalse(is_ransom_note("meeting_notes.txt"))

    def test_strip_suspicious_extension(self):
        self.assertEqual(strip_suspicious_extension("a/report.txt.locked"), "a/report.txt")
        self.assertIsNone(strip_suspicious_extension("a/report.txt"))

    def test_severity_levels(self):
        self.assertIsNone(severity_for(29))
        self.assertEqual(severity_for(30), "MEDIUM")
        self.assertEqual(severity_for(50), "HIGH")
        self.assertEqual(severity_for(80), "CRITICAL")
        self.assertEqual(total_score([Indicator("a", 70, ""), Indicator("b", 70, "")]), 100)

    def test_activity_tracker_window(self):
        tracker = ActivityTracker(window_seconds=60, threshold=3)
        for second in range(4):
            tracker.record(now=1000 + second)
        self.assertTrue(tracker.is_burst(now=1004))
        self.assertFalse(tracker.is_burst(now=1100))


if __name__ == "__main__":
    unittest.main()
