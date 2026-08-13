#!/usr/bin/env python3
"""Entry point for the honeypot/SIEM dashboard.

Run via ./run.sh (creates the venv and installs dependencies on first
use) rather than directly, unless you've already set up the venv
yourself -- see requirements.txt.
"""
import os
import sys

# Every site this app's embedded browsers ever point at (Kibana, the
# eshop) uses a self-signed cert with no real CA --
# ui/browser_widget.py's certificateError handler already accepts these
# unconditionally for normal page navigation and its subresource loads
# (it doesn't check origin either, same trade-off this makes), but
# confirmed live it does NOT cover every connection Chromium's network
# stack can open for a heavy page (WooCommerce/Elementor pull in dozens
# of JS/CSS/font subresources): a stray parallel/speculative connection
# occasionally fails the handshake with "certificate unknown" and lands
# in reverse_proxy's error log, even though every other resource on the
# same page load succeeds. Setting this before Chromium initializes
# covers those too, at the engine level -- a supplement to the existing
# signal handler (kept in place; still needed on some code paths), not a
# new category of risk beyond what that handler already accepted. Must
# be set before QtWebEngineWidgets is imported below -- Chromium reads
# this env var once, at engine startup.
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--ignore-certificate-errors")

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
