"""Kibana page: just browser_widget.BrowserWidget pointed at the configured
SIEM host's Kibana -- https://<remote_siem.host or localhost>:5601/. The
address bar is fully editable regardless (e.g. to navigate straight to a
specific saved dashboard's URL), this is only the starting point."""
from __future__ import annotations

from PyQt6.QtWidgets import QVBoxLayout, QWidget

from core.state import AppState
from ui.browser_widget import BrowserWidget

KIBANA_PORT = 5601


def _default_kibana_url(state: AppState) -> str:
    host = state.remote_siem.host if state.remote_siem.is_configured() else "localhost"
    return f"https://{host}:{KIBANA_PORT}/"


class KibanaPage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.browser = BrowserWidget(_default_kibana_url(state))
        layout.addWidget(self.browser)
