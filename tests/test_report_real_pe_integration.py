import unittest
from pathlib import Path

from core.modules import report


class ReportRealPeIntegrationTest(unittest.TestCase):
    def test_generate_report_with_safe_fixture_if_present(self):
        fixtures = sorted(Path("tests/fixtures").glob("*.exe")) + sorted(Path("tests/fixtures").glob("*.dll"))
        if not fixtures:
            self.skipTest("No safe PE fixture exists in tests/fixtures; integration test pending by policy.")

        pe_path = str(fixtures[0])
        data, html = report.generate_report(pe_path=pe_path, no_pdf_fail=True)
        self.assertIsInstance(data, dict)
        self.assertIsInstance(html, str)
        self.assertIn("schema_version", data)
        self.assertIn("Executive Summary", html)


if __name__ == "__main__":
    unittest.main()
