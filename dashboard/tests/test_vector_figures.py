"""Tests for core/vector_figures.py: report charts and diagrams must reach the
PDF as vector drawing, not as embedded bitmaps.

    cd dashboard && python3 -m unittest discover -s tests -v

Needs PyQt6, so it is skipped where PyQt6 isn't installed, like the Qt-free
CI job.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtCore import QMarginsF, QRectF, QSizeF
    from PyQt6.QtGui import QColor, QFont, QPageLayout, QPageSize, QPen, QTextDocument
    from PyQt6.QtPrintSupport import QPrinter
    from PyQt6.QtWidgets import QApplication
    from core import vector_figures as vf
except ImportError:  # PyQt6 missing
    vf = None


def _print(doc: "QTextDocument", path: str) -> bytes:
    printer = QPrinter(QPrinter.PrinterMode.ScreenResolution)
    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
    printer.setOutputFileName(path)
    printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    printer.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Unit.Millimeter)
    doc.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.DevicePixel).size()))
    doc.print(printer)
    with open(path, "rb") as fh:
        return fh.read()


@unittest.skipIf(vf is None, "PyQt6 not installed")
class VectorFigureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def _doc(self):
        doc = QTextDocument()
        fig, p = vf.new_figure(900, 300)
        p.setPen(QPen(QColor("#c62828"), 3))
        p.drawLine(20, 280, 880, 20)
        p.setFont(QFont("Serif", 14))
        p.drawText(QRectF(40, 40, 400, 40), "chart label")
        p.end()
        vf.add_figure(doc, "report://chart", fig)
        doc.setHtml('<p>Intro</p><p><img src="report://chart" width="520"/></p>'
                    '<table><tr><td><img src="report://chart" width="300"/></td></tr></table>')
        return doc

    def test_registered_images_are_replaced(self):
        doc = self._doc()
        self.assertEqual(vf.embed_figures(doc), 2)

    def test_pdf_has_no_bitmaps(self):
        doc = self._doc()
        vf.embed_figures(doc)
        with tempfile.TemporaryDirectory() as tmp:
            pdf = _print(doc, os.path.join(tmp, "v.pdf"))
        self.assertNotIn(b"/Subtype /Image", pdf)

    def test_without_embedding_it_is_a_bitmap(self):
        # The raster fallback: an <img> never swapped still shows the figure.
        doc = self._doc()
        with tempfile.TemporaryDirectory() as tmp:
            pdf = _print(doc, os.path.join(tmp, "r.pdf"))
        self.assertIn(b"/Subtype /Image", pdf)

    def test_figure_keeps_its_aspect_ratio(self):
        doc = self._doc()
        vf.embed_figures(doc)
        doc.setTextWidth(700)
        block = doc.begin().next()  # the paragraph holding the 520-wide figure
        self.assertAlmostEqual(block.layout().lineAt(0).height(), 520 * 300 / 900, delta=6)


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(vf is None, "PyQt6 not installed")
class RoutingDecisionDiagramTests(unittest.TestCase):
    """The routing-decision figure in the exploit report PDF."""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_renders_as_vector(self):
        from core import diagrams
        doc = QTextDocument()
        html = diagrams.figure_html(doc, diagrams.routing_decision_diagram(), "decision", 3, "x")
        doc.setHtml(html)
        self.assertEqual(vf.embed_figures(doc), 1)
        with tempfile.TemporaryDirectory() as tmp:
            pdf = _print(doc, os.path.join(tmp, "d.pdf"))
        self.assertNotIn(b"/Subtype /Image", pdf)

    def test_covers_every_router_stage(self):
        # Each honeypot stage in router.lua's decide_route has a row; a new
        # stage there should get one here too.
        router = (Path(__file__).resolve().parents[2]
                  / "ids/reverse_proxy_enhanced/lua/router.lua").read_text()
        reasons = {"high_threat_score", "cve_pattern_match", "vulnerable_plugin_access",
                   "bad_ip_reputation", "multiple_admin_attempts",
                   "accumulated_suspicious_activities", "rapid_automation_detected",
                   "suspicious_file_upload"}
        for r in reasons:
            self.assertIn(f'"{r}"', router, r)
        src = (Path(__file__).resolve().parents[1] / "core/diagrams.py").read_text()
        body = src.split("def routing_decision_diagram", 1)[1].split("\ndef ", 1)[0]
        stage_rows = [k for k in ("s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10")
                      if f'("{k}", "dec"' in body]
        self.assertEqual(len(stage_rows), len(reasons) + 1)  # + sticky re-check
