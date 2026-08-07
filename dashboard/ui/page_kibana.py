"""Kibana page: browser_widget.BrowserWidget pointed at the configured SIEM
host's Kibana -- https://<remote_siem.host or localhost>:5601/. The address
bar is fully editable regardless (e.g. to navigate straight to a specific
saved dashboard's URL), this is only the starting point.

Two things beyond a bare embedded browser:
  - "Remember credentials" (default on): toggles between a persistent
    (named) QWebEngineProfile and the off-the-record default every other
    embedded browser in this app uses -- see browser_widget.py. Kibana is
    the one place in this app where staying logged in across restarts is
    obviously wanted, unlike the Exploits page's eshop browser.
  - A causality banner on load failure: QWebEngineView's own error page
    just says something generic like "can't reach this page", with no way
    for the user to tell "is the SIEM stack down, or something else" --
    this checks whether Kibana's own container is actually running and
    says so explicitly, since "reachable but broken" and "not running at
    all" call for different next steps.
"""
from __future__ import annotations

from PyQt6.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from core.docker_ctl import Target
from core.state import AppState
from ui.browser_widget import BrowserWidget

KIBANA_PORT = 5601
_PROFILE_NAME = "kibana_dashboard"


def _default_kibana_url(state: AppState) -> str:
    host = state.remote_siem.host if state.remote_siem.is_configured() else "localhost"
    return f"https://{host}:{KIBANA_PORT}/"


class KibanaPage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(6, 6, 6, 0)
        self.remember_check = QCheckBox("Remember credentials (keep me logged in across restarts)")
        self.remember_check.setChecked(state.kibana_remember_credentials)
        self.remember_check.toggled.connect(self._on_remember_toggled)
        toolbar.addWidget(self.remember_check)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self.banner = QLabel("")
        self.banner.setWordWrap(True)
        self.banner.setVisible(False)
        self.banner.setStyleSheet(
            "QLabel { background-color: #d9534f; color: white; padding: 8px; }"
        )
        layout.addWidget(self.banner)

        self._browser_layout = QVBoxLayout()
        self._browser_layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(self._browser_layout, stretch=1)

        self.browser: BrowserWidget | None = None
        self._build_browser()

    def _build_browser(self) -> None:
        profile_name = _PROFILE_NAME if self.state.kibana_remember_credentials else None
        self.browser = BrowserWidget(_default_kibana_url(self.state), profile_name=profile_name)
        self.browser.view.loadFinished.connect(self._on_load_finished)
        self._browser_layout.addWidget(self.browser)

    def _on_remember_toggled(self, checked: bool) -> None:
        self.state.kibana_remember_credentials = checked
        self.state.save()

        # Swapping which QWebEngineProfile is in use means a different
        # cookie/cache store entirely -- can't just flip a flag on the
        # existing view, the browser has to be rebuilt against the new
        # profile. Whatever page was loaded is lost; that's an inherent
        # consequence of switching storage, not a bug.
        old = self.browser
        self._browser_layout.removeWidget(old)
        old.deleteLater()
        self.banner.setVisible(False)
        self._build_browser()

    def _on_load_finished(self, ok: bool) -> None:
        if ok:
            self.banner.setVisible(False)
            return

        remote = self.state.remote_siem if self.state.remote_siem.is_configured() else None
        target = Target(project="siem", remote=remote)
        containers = target.ps()
        kibana_container = next((c for c in containers if c.get("Service") == "kibana"), None)

        if kibana_container is None:
            self.banner.setText(
                "⚠ Couldn't load Kibana because the SIEM stack doesn't appear to be running "
                f"at all for this target ({target.label}) -- no 'kibana' container found. "
                "Start it from the Services page, then reload this page."
            )
        elif kibana_container.get("State") != "running":
            self.banner.setText(
                "⚠ Couldn't load Kibana -- its container exists but isn't running "
                f"(state: {kibana_container.get('State', 'unknown')}). Start it from the "
                "Services page, then reload this page."
            )
        else:
            self.banner.setText(
                "⚠ Couldn't load Kibana -- its container IS running, so this isn't a "
                "\"SIEM is down\" problem. Check its logs on the Services/Health page "
                "(startup can take a minute; a cert/network issue would also show here)."
            )
        self.banner.setVisible(True)
