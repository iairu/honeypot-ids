#!/usr/bin/env python3
"""Entry point for the honeypot/SIEM dashboard.

Run via ./run.sh (creates the venv and installs dependencies on first
use) rather than directly, unless you've already set up the venv
yourself -- see requirements.txt.
"""
import sys

from PyQt6.QtWidgets import QApplication

from core.state import AppState
from ui.main_window import MainWindow
from ui.wizard import SetupWizard


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Honeypot Dashboard")
    app.setOrganizationName("DP_Repository")

    state = AppState.load()

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
