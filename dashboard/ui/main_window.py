"""Main application window: sidebar navigation between Services / Health /
Certificates / Settings, a menu bar (Settings menu + re-run wizard), a
shared background status poller, and window-geometry persistence."""
from __future__ import annotations

import base64

from PyQt6.QtCore import QByteArray
from PyQt6.QtWidgets import (
    QListWidget, QListWidgetItem, QMainWindow, QMenuBar, QSplitter,
    QStackedWidget, QWidget,
)

from core.docker_ctl import all_targets
from core.state import AppState
from ui.page_certs import CertsPage
from ui.page_health import HealthPage
from ui.page_services import ServicesPage
from ui.page_settings import SettingsPage
from ui.status_poller import StatusPoller
from ui.wizard import SetupWizard

PAGES = ["services", "health", "certificates", "settings"]
PAGE_LABELS = {
    "services": "Services",
    "health": "Health",
    "certificates": "Certificates",
    "settings": "Settings",
}


class MainWindow(QMainWindow):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self.setWindowTitle("Honeypot / SIEM Dashboard")
        self.resize(1200, 800)
        self._restore_geometry()

        self._build_menu()

        splitter = QSplitter()
        self.setCentralWidget(splitter)

        self.nav_list = QListWidget()
        self.nav_list.setMaximumWidth(180)
        for page_id in PAGES:
            item = QListWidgetItem(PAGE_LABELS[page_id])
            item.setData(1, page_id)
            self.nav_list.addItem(item)
        self.nav_list.currentRowChanged.connect(self._on_nav_changed)
        splitter.addWidget(self.nav_list)

        self.stack = QStackedWidget()
        splitter.addWidget(self.stack)
        splitter.setSizes([180, 1020])

        self.services_page = ServicesPage(self._get_targets)
        self.health_page = HealthPage(self._get_targets)
        self.certs_page = CertsPage()
        self.settings_page = SettingsPage(state, self._on_remote_settings_changed)

        for page_id, widget in [
            ("services", self.services_page),
            ("health", self.health_page),
            ("certificates", self.certs_page),
            ("settings", self.settings_page),
        ]:
            self.stack.addWidget(widget)

        start_index = PAGES.index(state.last_page) if state.last_page in PAGES else 0
        self.nav_list.setCurrentRow(start_index)

        self.poller = StatusPoller(self._get_targets, interval_ms=5000)
        self.poller.results_ready.connect(self._on_status_results)
        self.poller.start()

    # ---- navigation / target plumbing ----

    def _get_targets(self):
        return all_targets(self.state.remote_edge, self.state.remote_siem)

    def _on_nav_changed(self, row: int) -> None:
        if 0 <= row < len(PAGES):
            self.stack.setCurrentIndex(row)
            self.state.last_page = PAGES[row]
            self.state.save()

    def _on_remote_settings_changed(self) -> None:
        self.services_page.rebuild_panels()
        # Health page rebuilds its diagram automatically on the next poll
        # tick (it always calls _get_targets() fresh in apply_status()).

    def _on_status_results(self, results: dict) -> None:
        self.services_page.apply_status(results)
        self.health_page.apply_status(results)

    # ---- menu ----

    def _build_menu(self) -> None:
        menu_bar: QMenuBar = self.menuBar()

        settings_menu = menu_bar.addMenu("&Settings")
        open_settings_action = settings_menu.addAction("Open Settings page")
        open_settings_action.triggered.connect(lambda: self.nav_list.setCurrentRow(PAGES.index("settings")))
        rerun_wizard_action = settings_menu.addAction("Re-run setup wizard…")
        rerun_wizard_action.triggered.connect(self._rerun_wizard)

        view_menu = menu_bar.addMenu("&View")
        for page_id in PAGES:
            action = view_menu.addAction(PAGE_LABELS[page_id])
            action.triggered.connect(lambda _checked, pid=page_id: self.nav_list.setCurrentRow(PAGES.index(pid)))

    def _rerun_wizard(self) -> None:
        wizard = SetupWizard(self.state, self)
        wizard.exec()
        # Settings page holds its own EnvFile/RemoteConfigWidget instances
        # loaded at construction time -- rebuild it so it reflects whatever
        # the wizard just wrote, instead of showing stale pre-wizard values.
        self._reload_settings_page()
        self.services_page.rebuild_panels()

    def _reload_settings_page(self) -> None:
        index = self.stack.indexOf(self.settings_page)
        self.stack.removeWidget(self.settings_page)
        self.settings_page.deleteLater()
        self.settings_page = SettingsPage(self.state, self._on_remote_settings_changed)
        self.stack.insertWidget(index, self.settings_page)

    # ---- geometry persistence ----

    def _restore_geometry(self) -> None:
        if self.state.window_geometry_b64:
            try:
                data = QByteArray(base64.b64decode(self.state.window_geometry_b64))
                self.restoreGeometry(data)
            except Exception:
                pass

    def closeEvent(self, event) -> None:
        data = bytes(self.saveGeometry())
        self.state.window_geometry_b64 = base64.b64encode(data).decode("ascii")
        self.state.save()
        self.poller.stop()
        self.poller.wait(2000)
        super().closeEvent(event)
