#!/usr/bin/env python3
"""First-run setup progress window -- run by run.sh AFTER PyQt6 itself is
already installed into the venv, alone, first. That ordering is what
makes this possible at all: no GUI toolkit exists yet the moment run.sh
starts (that's the whole reason a plain venv+pip bootstrap normally shows
nothing), but PyQt6 alone is a comparatively small/fast install -- as
soon as it's done, this script uses PyQt6 itself to show real graphical
progress for installing everything else in requirements.txt.
PyQt6-WebEngine in particular is a large download (it bundles a Chromium
build), so that's exactly the part of first-run setup most worth showing
progress for -- especially when launched from Dashboard.desktop
(Terminal=false), where nothing printed to stdout is visible at all and
the window would otherwise just silently not appear for a minute or two.

Standalone by design: doesn't import anything from core/ui (those assume
a fully set-up environment -- this script's whole job is to still be
building it), just PyQt6 and the standard library.
"""
from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import QProcess, QTimer
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QLabel, QProgressBar, QPushButton, QVBoxLayout, QWidget

DASHBOARD_DIR = Path(__file__).resolve().parent
VENV_PIP = DASHBOARD_DIR / "venv" / "bin" / "pip"
REQUIREMENTS = DASHBOARD_DIR / "requirements.txt"
APP_ICON_PATH = DASHBOARD_DIR / "resources" / "app_icon.svg"


def _remaining_requirements() -> list[str]:
    """Every requirements.txt line except PyQt6 itself -- run.sh already
    installed that one alone, before this script could even exist (it
    needs PyQt6 importable just to start)."""
    lines = []
    for line in REQUIREMENTS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("PyQt6=="):
            continue
        lines.append(line)
    return lines


class SetupWindow(QWidget):
    def __init__(self, requirements: list[str]):
        super().__init__()
        self.setWindowTitle("Setting up Honeypot Dashboard…")
        self.setFixedSize(440, 130)
        if APP_ICON_PATH.exists():
            self.setWindowIcon(QIcon(str(APP_ICON_PATH)))

        self._requirements = requirements
        # PyQt6 itself was already installed by run.sh before this script
        # could run -- counted here so the bar doesn't start at 0% for
        # work that's already done.
        self._total = len(requirements) + 1
        self._done = 1
        self._process: QProcess | None = None
        self.failed = False

        layout = QVBoxLayout(self)
        self.status_label = QLabel("First run -- installing dependencies (PyQt6 done)…")
        layout.addWidget(self.status_label)

        self.progress = QProgressBar()
        self.progress.setRange(0, self._total)
        self.progress.setValue(self._done)
        layout.addWidget(self.progress)

        self.detail_label = QLabel("")
        self.detail_label.setStyleSheet("color: #888888; font-size: 11px;")
        self.detail_label.setWordWrap(True)
        layout.addWidget(self.detail_label)

        self.close_btn = QPushButton("Close")
        self.close_btn.setVisible(False)
        self.close_btn.clicked.connect(self.close)
        layout.addWidget(self.close_btn)

        # Deferred, not called directly from __init__: lets this window
        # actually paint and become visible first -- starting the QProcess
        # synchronously here would otherwise let the first pip install
        # begin (and potentially finish, for a tiny package) before the
        # window has ever been shown on screen.
        QTimer.singleShot(0, self._install_next)

    def _install_next(self) -> None:
        if not self._requirements:
            self.status_label.setText("Setup complete -- starting dashboard…")
            self.detail_label.setText("")
            self.progress.setValue(self._total)
            # Brief pause so "Setup complete" is actually readable rather
            # than the window vanishing the instant the last install exits.
            QTimer.singleShot(600, QApplication.instance().quit)
            return

        pkg = self._requirements.pop(0)
        self.status_label.setText(f"Installing {pkg}…  ({self._done}/{self._total})")
        self.detail_label.setText("")

        self._process = QProcess(self)
        self._process.setProgram(str(VENV_PIP))
        # No -q: pip's own download-progress text ("Downloading ... 45%")
        # is exactly the live sub-progress worth surfacing in detail_label
        # for a large package like PyQt6-WebEngine -- quiet mode would
        # leave that label blank for the entire multi-minute download.
        self._process.setArguments(["install", pkg])
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_output)
        self._process.finished.connect(self._on_finished)
        self._process.start()

    def _on_output(self) -> None:
        data = self._process.readAllStandardOutput().data().decode(errors="replace")
        # pip's download-progress line overwrites in place via \r, not
        # \n -- splitting on both and taking the last non-empty fragment
        # is what actually surfaces that live text instead of an empty
        # string (a \r-only chunk splits to [''] on \n alone).
        fragments = [f.strip() for f in data.replace("\r", "\n").split("\n") if f.strip()]
        if fragments:
            self.detail_label.setText(fragments[-1])

    def _on_finished(self, exit_code: int, _exit_status) -> None:
        if exit_code != 0:
            self.failed = True
            self.status_label.setText("✗ Setup failed installing a package -- see terminal output for details.")
            self.status_label.setStyleSheet("color: #d9534f;")
            self.close_btn.setVisible(True)
            return

        self._done += 1
        self.progress.setValue(self._done)
        self._install_next()


def main() -> int:
    app = QApplication(sys.argv)
    window = SetupWindow(_remaining_requirements())
    window.show()
    app.exec()
    return 1 if window.failed else 0


if __name__ == "__main__":
    sys.exit(main())
