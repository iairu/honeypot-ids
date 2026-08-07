#!/usr/bin/env python3
"""Entry point for the honeypot/SIEM dashboard.

Run via ./run.sh (creates the venv and installs dependencies on first
use) rather than directly, unless you've already set up the venv
yourself -- see requirements.txt.
"""
import sys

# Must be imported before the QApplication instance is constructed below --
# PyQt6 raises ImportError otherwise ("QtWebEngineWidgets must be imported
# or Qt.AA_ShareOpenGLContexts must be set before a QCoreApplication
# instance is created"). Only main.py's import order matters here; every
# other module that touches QWebEngineView (ui/browser_widget.py etc.) can
# import it normally since by the time those run, this has already fired.
from PyQt6 import QtWebEngineWidgets  # noqa: F401
from PyQt6.QtWidgets import QApplication

from core.state import AppState
from ui import theme
from ui.main_window import MainWindow
from ui.wizard import SetupWizard


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Honeypot Dashboard")
    app.setOrganizationName("DP_Repository")

    state = AppState.load()
    theme.apply_theme(state.theme)

    if not state.first_run_complete:
        wizard = SetupWizard(state)
        result = wizard.exec()
        if result != SetupWizard.DialogCode.Accepted:
            # User cancelled first-run setup entirely -- nothing usable
            # exists yet (no confirmed .env), so exit rather than open a
            # main window pointed at an unconfigured/half-configured stack.
            return 0
        state = AppState.load()  # SetupWizard.accept() already saved it

    window = MainWindow(state)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
