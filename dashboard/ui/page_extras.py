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
            "Auto-generated PDF exports, all rendered in the same Baskerville face as the "
            "exploit report:<br/>"
            "&bull; <b>Implementation chapter</b> &ndash; the project's more interesting "
            "algorithms, pulled from the source and condensed (comments, docstrings, debug "
            "logging and blank runs removed), plus a services overview and a Health-page shot.<br/>"
            "&bull; <b>Architecture &amp; services</b> &ndash; every service on this branch with "
            "its role, plus the live Health page.<br/>"
            "&bull; <b>Exploit / CVE matrix</b> &ndash; a reference table of every exploit "
            "preset the dashboard can fire.")
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #aaaaaa;")
        layout.addWidget(intro)

        toolbar = QHBoxLayout()
        self.export_btn = QPushButton("Implementation chapter (PDF)")
        self.export_btn.clicked.connect(lambda: self._run_export(
            "implementation chapter", "implementation_chapter.pdf",
            lambda path, hs: thesis_export.render_thesis_pdf(path, health_screenshot=hs),
            needs_health=True))
        toolbar.addWidget(self.export_btn)

        self.arch_btn = QPushButton("Architecture & services (PDF)")
        self.arch_btn.setToolTip("Every service on this branch with its role, plus the live Health page.")
        self.arch_btn.clicked.connect(lambda: self._run_export(
            "architecture overview", "architecture_overview.pdf",
            lambda path, hs: thesis_export.render_architecture_pdf(path, health_screenshot=hs),
            needs_health=True))
        toolbar.addWidget(self.arch_btn)

        self.cve_btn = QPushButton("Exploit / CVE matrix (PDF)")
        self.cve_btn.setToolTip("Reference table of every exploit preset the dashboard can fire.")
        self.cve_btn.clicked.connect(lambda: self._run_export(
            "exploit / CVE matrix", "cve_coverage.pdf",
            lambda path, hs: thesis_export.render_cve_matrix_pdf(path),
            needs_health=False))
        toolbar.addWidget(self.cve_btn)

        self.refresh_btn = QPushButton("Refresh preview")
        self.refresh_btn.clicked.connect(self._reload_preview)
        toolbar.addWidget(self.refresh_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)
        self._export_buttons = [self.export_btn, self.arch_btn, self.cve_btn]

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

    def _run_export(self, label: str, default_name: str, render_fn, needs_health: bool) -> None:
        """Generic PDF export: ask for a path, grab the Health page if the export
        needs it, run render_fn(path, health_shot) on the GUI thread (the renders
        are quick), and offer to open the result."""
        path, _ = QFileDialog.getSaveFileName(
            self, f"Save {label}", default_name, "PDF files (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"

        for b in self._export_buttons:
            b.setEnabled(False)
        QGuiApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        health_shot = ""
        if needs_health and self._health_screenshot_provider is not None:
            try:
                health_shot = self._health_screenshot_provider() or ""
            except Exception:  # noqa: BLE001 -- never let a grab failure block export
                health_shot = ""
        try:
            render_fn(path, health_shot)
        except Exception as e:  # noqa: BLE001 -- surface any render failure to the user
            QGuiApplication.restoreOverrideCursor()
            for b in self._export_buttons:
                b.setEnabled(True)
            self.status_label.setText(f"✗ Export failed: {e}")
            self.status_label.setStyleSheet("color: #d9534f;")
            QMessageBox.warning(self, "Export failed", str(e))
            return
        QGuiApplication.restoreOverrideCursor()
        for b in self._export_buttons:
            b.setEnabled(True)
        self.status_label.setText(f"✓ Saved {label} to: {path}")
        self.status_label.setStyleSheet("color: #5cb85c;")
        if QMessageBox.question(
            self, "Saved",
            f"Saved the {label} to:\n{path}\n\nOpen it now?",
        ) == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))
