import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from mailposture.cli import main


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_text_report(self):
        code, out, _ = run(["example.com", "--demo", "weak"])
        self.assertEqual(code, 0)
        self.assertIn("Grade F", out)
        self.assertIn("SPF exceeds the 10-DNS-lookup limit", out)

    def test_json_report(self):
        code, out, _ = run(["example.com", "--demo", "weak", "--format", "json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["domain"], "example.com")
        self.assertEqual(payload["grade"], "F")

    def test_html_report(self):
        code, out, _ = run(["example.org", "--demo", "good", "--format", "html"])
        self.assertEqual(code, 0)
        self.assertIn("<table>", out)
        self.assertIn("Grade A", out)

    def test_min_grade_gate(self):
        code, _, err = run(["example.com", "--demo", "weak", "--min-grade", "A"])
        self.assertEqual(code, 1)
        self.assertIn("below required", err)

    def test_min_grade_passes(self):
        code, _, _ = run(["example.org", "--demo", "good", "--min-grade", "A"])
        self.assertEqual(code, 0)

    def test_out_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "audit.json"
            code, _, err = run(["example.com", "--demo", "weak",
                                "--format", "json", "--out", str(target)])
            self.assertEqual(code, 0)
            self.assertIn("wrote", err)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["grade"], "F")

    def test_extra_selector_does_not_crash(self):
        code, _, _ = run(["example.com", "--demo", "weak",
                          "--selector", "custom123"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
