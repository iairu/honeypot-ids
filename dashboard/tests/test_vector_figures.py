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
