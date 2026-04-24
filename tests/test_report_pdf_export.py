import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import builtins

from core.modules import report


class ReportPdfExportTest(unittest.TestCase):
    def test_export_pdf_missing_weasyprint_is_graceful(self):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "weasyprint":
                raise ImportError("forced missing weasyprint")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            msg = report.export_pdf_from_html("<html><body>x</body></html>", "/tmp/noop.pdf")
        self.assertIsInstance(msg, str)
        self.assertIn("missing dependency 'weasyprint'", msg)

    def test_generate_report_graceful_mode_does_not_block_html_json(self):
        fake_data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-PDF", "examiner": "QA", "analyst_notes": "pdf graceful"},
            "meta": {"path": "sample.exe"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
        }
        with tempfile.TemporaryDirectory() as d:
            html_path = Path(d) / "out.html"
            json_path = Path(d) / "out.json"
            pdf_path = Path(d) / "out.pdf"

            with patch("core.modules.report.build_data", return_value=dict(fake_data)), \
                 patch("core.modules.report.render_html", return_value="<html><body>ok</body></html>"), \
                 patch("core.modules.report.export_pdf_from_html", return_value="PDF export unavailable: missing dependency 'weasyprint'. Install with: pip install weasyprint"):
                data, html = report.generate_report(
                    pe_path="dummy.exe",
                    html_path=str(html_path),
                    json_path=str(json_path),
                    pdf_path=str(pdf_path),
                    no_pdf_fail=True,
                )

            self.assertIn("ok", html)
            self.assertTrue(html_path.exists())
            self.assertTrue(json_path.exists())
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload.get("schema_version"), "erevos.report.v2")
            self.assertTrue(any("PDF export unavailable" in n for n in (data.get("notes") or [])))

    def test_generate_report_hard_fail_mode_raises_on_pdf_error(self):
        fake_data = {
            "schema_version": "erevos.report.v2",
            "case": {},
            "meta": {},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
        }
        with patch("core.modules.report.build_data", return_value=dict(fake_data)), \
             patch("core.modules.report.render_html", return_value="<html><body>ok</body></html>"), \
             patch("core.modules.report.export_pdf_from_html", return_value="PDF export failed: backend unavailable"):
            with self.assertRaises(RuntimeError):
                report.generate_report(
                    pe_path="dummy.exe",
                    pdf_path="/tmp/out.pdf",
                    no_pdf_fail=False,
                )


if __name__ == "__main__":
    unittest.main()
