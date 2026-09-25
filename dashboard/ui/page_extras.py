"""Extras page: one-click export of an auto-generated "Implementation" thesis
chapter (PDF) built from the project's more interesting algorithms.

The heavy lifting is in core/thesis_export: it reads the featured excerpts out
of the live source tree, condenses them, and renders a Baskerville PDF. This
page is just the button plus a preview of what will be included (entries whose
source is absent on the current branch are skipped, so the list reflects this
checkout)."""
from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QDesktopServices, QGuiApplication
from PyQt6.QtCore import QUrl
from PyQt6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QMessageBox, QPushButton, QVBoxLayout, QWidget,
)

from core import thesis_export


class ExtrasPage(QWidget):
    def __init__(self, health_screenshot_provider=None, parent=None):
        super().__init__(parent)
        # Callable returning a PNG path of the Health page (or "" on failure);
        # supplied by MainWindow, which alone can bring that page on-screen to
        # grab it. None => the chapter is exported without the screenshot.
        self._health_screenshot_provider = health_screenshot_provider
        layout = QVBoxLayout(self)

        title = QLabel("Extras")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(title)

        intro = QLabel(
            "Export an auto-generated <b>Implementation</b> chapter (PDF): a curated set of "
            "the project's more interesting algorithms, pulled straight from the source and "
            "condensed (comments, docstrings, debug logging and blank runs removed) so only "
            "the algorithmic essence is shown. Rendered in the same Baskerville face as the "
            "exploit report.")
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #aaaaaa;")
        layout.addWidget(intro)

        toolbar = QHBoxLayout()
        self.export_btn = QPushButton("Export implementation chapter (PDF)")
        self.export_btn.clicked.connect(self._export)
        toolbar.addWidget(self.export_btn)
        self.refresh_btn = QPushButton("Refresh preview")
        self.refresh_btn.clicked.connect(self._reload_preview)
        toolbar.addWidget(self.refresh_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self.count_label = QLabel("")
        self.count_label.setStyleSheet("color: #888888;")
        layout.addWidget(self.count_label)

        layout.addWidget(QLabel("Excerpts that will be included on this branch:"))
        self.preview = QListWidget()
        layout.addWidget(self.preview, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self._reload_preview()

    def _reload_preview(self) -> None:
        self.preview.clear()
        try:
            items = thesis_export.available_highlights()
        except Exception as e:  # noqa: BLE001 -- never let a scan error break the page
            self.count_label.setText(f"Could not scan sources: {e}")
            return
        last_section = None
        for hl, code in items:
            if hl.section != last_section:
                header = QListWidgetItem(f"— {hl.section} —")
                header.setFlags(Qt.ItemFlag.NoItemFlags)
                self.preview.addItem(header)
                last_section = hl.section
            lines = len(code.splitlines())
            self.preview.addItem(
                QListWidgetItem(f"    {hl.title}   ({hl.lang}, {lines} lines) — {hl.path}"))
        self.count_label.setText(f"{len(items)} excerpt(s) resolved from the source tree.")

    def _export(self) -> None:
        items = thesis_export.available_highlights()
        if not items:
            QMessageBox.warning(
                self, "Nothing to export",
                "No featured excerpts could be resolved from the source tree on this "
                "branch. Nothing was written.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save implementation chapter", "implementation_chapter.pdf",
            "PDF files (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"

        self.export_btn.setEnabled(False)
        QGuiApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        # Grab the Health page for the "Services and health" section (best
        # effort -- the chapter still exports if this fails).
        health_shot = ""
        if self._health_screenshot_provider is not None:
            try:
                health_shot = self._health_screenshot_provider() or ""
            except Exception:  # noqa: BLE001 -- never let a grab failure block export
                health_shot = ""
        try:
            n = thesis_export.render_thesis_pdf(path, health_screenshot=health_shot)
        except Exception as e:  # noqa: BLE001 -- surface any render failure to the user
            QGuiApplication.restoreOverrideCursor()
            self.export_btn.setEnabled(True)
            self.status_label.setText(f"✗ Export failed: {e}")
            self.status_label.setStyleSheet("color: #d9534f;")
            QMessageBox.warning(self, "Export failed", str(e))
            return
        QGuiApplication.restoreOverrideCursor()
        self.export_btn.setEnabled(True)
        self.status_label.setText(f"✓ Saved {n} excerpt(s) to: {path}")
        self.status_label.setStyleSheet("color: #5cb85c;")
        if QMessageBox.question(
            self, "Chapter saved",
            f"Saved the implementation chapter to:\n{path}\n\nOpen it now?",
        ) == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))
