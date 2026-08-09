"""Main application window: sidebar navigation between Services / Health /
Certificates / Settings, a menu bar (Settings menu + re-run wizard), a
shared background status poller, window-geometry persistence, a system
tray icon (unhealthy-container notifications), and a confirm-before-quit
guard while a mutating docker compose action is in flight."""
from __future__ import annotations

import base64

from PyQt6.QtCore import QByteArray
from PyQt6.QtGui import QIcon, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QListWidget, QListWidgetItem, QMainWindow, QMenu, QMenuBar, QMessageBox,
    QSplitter, QStackedWidget, QSystemTrayIcon, QVBoxLayout, QWidget,
)

from core.docker_ctl import Target, all_targets
from core.paths import DASHBOARD_DIR
from core.state import AppState
from ui.dependency_banner import DependencyBanner
from ui.health_diagram import classify
from ui.page_backups import BackupsPage
from ui.page_certs import CertsPage
from ui.page_exploits import ExploitsPage
from ui.page_health import HealthPage
from ui.page_kibana import KibanaPage
from ui.page_log_search import LogSearchPage
from ui.page_redis import RedisPage
from ui.page_services import ServicesPage
from ui.page_settings import SettingsPage
from ui.security_feed import SecurityEventFeed
from ui.status_poller import StatusPoller
from ui.wizard import SetupWizard

# Bundled instead of relying on QIcon.fromTheme() -- confirmed live that
# "utilities-system-monitor" resolves to a NULL icon on this window
# manager/icon theme, which QSystemTrayIcon happily accepts and then shows
# as blank, clickable empty space in the tray rather than erroring or
# falling back to anything. A file shipped in the repo works the same
# regardless of the host's icon theme.
_APP_ICON_PATH = DASHBOARD_DIR / "resources" / "app_icon.svg"

# Statuses (see ui.health_diagram.classify()) worth a tray notification when
# a container transitions INTO them. Deliberately excludes "down" (a
# container simply not running -- e.g. before the user has hit Start -- is
# the normal resting state, not a problem) and "exited_ok" (a one-shot job
# finishing cleanly is success, not something to alarm about).
_NOTIFY_ON_STATUSES = {"unhealthy", "exited_bad"}

PAGES = [
    "services", "health", "certificates", "redis", "backups", "kibana",
    "exploits", "log_search", "settings",
]
PAGE_LABELS = {
    "services": "Services",
    "health": "Health",
    "certificates": "Certificates",
    "redis": "Redis",
    "backups": "Backups",
    "kibana": "Kibana",
    "exploits": "Exploits",
    "log_search": "Log Search",
    "settings": "Settings",
}


class MainWindow(QMainWindow):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self.setWindowTitle("Honeypot / SIEM Dashboard")
        self.resize(1200, 800)
        if _APP_ICON_PATH.exists():
            self.setWindowIcon(QIcon(str(_APP_ICON_PATH)))
        self._restore_geometry()

        self._build_menu()

        central = QWidget()
        central_layout = QVBoxLayout(central)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)
        self.setCentralWidget(central)

        # Persistent across every page (unlike a per-page banner, this
        # can't be missed just because docker/docker compose happened to
        # be fine when whichever page you're currently on was built).
        self.dependency_banner = DependencyBanner()
        central_layout.addWidget(self.dependency_banner)

        splitter = QSplitter()
        central_layout.addWidget(splitter, stretch=1)

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

        # App-lifetime background tail of reverse_proxy's logs, independent
        # of whether the Exploits page is open -- persists notable events
        # (honeypot diversions, CVE/high-severity signals, missing
        # dependencies) to AppState.security_events across restarts. No
        # page currently displays this (see ui/security_feed.py); kept
        # running since the underlying data collection is independently
        # useful and the cost is one background log tail.
        self.security_feed = SecurityEventFeed(state, self)
        self.security_feed.start(self._edge_target())

        self.services_page = ServicesPage(self._get_targets)
        self.health_page = HealthPage(self._get_targets)
        self.certs_page = CertsPage()
        self.redis_page = RedisPage(state)
        self.backups_page = BackupsPage(state)
        self.kibana_page = KibanaPage(state)
        self.exploits_page = ExploitsPage(state)
        self.log_search_page = LogSearchPage(state)
        self.settings_page = SettingsPage(state, self._on_remote_settings_changed, self.set_poll_interval)

        for page_id, widget in [
            ("services", self.services_page),
            ("health", self.health_page),
            ("certificates", self.certs_page),
            ("redis", self.redis_page),
            ("backups", self.backups_page),
            ("kibana", self.kibana_page),
            ("exploits", self.exploits_page),
            ("log_search", self.log_search_page),
            ("settings", self.settings_page),
        ]:
            self.stack.addWidget(widget)

        start_index = PAGES.index(state.last_page) if state.last_page in PAGES else 0
        self.nav_list.setCurrentRow(start_index)

        self.poller = StatusPoller(self._get_targets, interval_ms=state.poll_interval_ms)
        self.poller.results_ready.connect(self._on_status_results)
        self.poller.start()

        # Previous poll's classified status per (target_key, service), used
        # to detect NEW unhealthy/exited-with-error transitions rather than
        # re-notifying on every single poll tick while a container just sits
        # unhealthy.
        self._last_status: dict[tuple[str, str], str] = {}

        self._build_tray_icon()

        # A required tool going missing is recorded into the same
        # persisted security-events history as everything else the feed
        # tracks, not just this banner's own standing warning.
        self.dependency_banner.required_missing_detected.connect(self.security_feed.add_dependency_event)

        self._build_shortcuts()

    # ---- navigation / target plumbing ----

    def _get_targets(self):
        return all_targets(self.state.remote_edge, self.state.remote_siem)

    def _edge_target(self) -> Target:
        """Same target selection logic as page_exploits.py's own -- the
        security feed tails the same reverse_proxy the Exploits page's
        score badge does."""
        remote = self.state.remote_edge if self.state.remote_edge.is_configured() else None
        return Target(project="edge", remote=remote)

    def _on_nav_changed(self, row: int) -> None:
        if 0 <= row < len(PAGES):
            self.stack.setCurrentIndex(row)
            self.state.last_page = PAGES[row]
            self.state.save()

    def _on_remote_settings_changed(self) -> None:
        self.services_page.rebuild_panels()
        # Health page rebuilds its diagram automatically on the next poll
        # tick (it always calls _get_targets() fresh in apply_status()).
        self.redis_page.rebuild_targets()
        self.backups_page.rebuild_targets()
        self.exploits_page.rebuild_targets()
        self.log_search_page.rebuild_targets()
        self.security_feed.start(self._edge_target())

    def set_poll_interval(self, interval_ms: int) -> None:
        self.state.poll_interval_ms = interval_ms
        self.state.save()
        self.poller.set_interval(interval_ms)

    def _on_status_results(self, results: dict) -> None:
        self.services_page.apply_status(results)
        self.health_page.apply_status(results)
        self.exploits_page.apply_status(results)
        self._notify_new_problems(results)

    # ---- system tray ----

    def _build_tray_icon(self) -> None:
        self.tray_icon = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            # Headless/offscreen environments and some minimal window
            # managers have no tray at all -- notifications are simply
            # unavailable there, not an error.
            return

        icon = QIcon(str(_APP_ICON_PATH)) if _APP_ICON_PATH.exists() else QIcon()
        if icon.isNull():
            icon = QIcon.fromTheme("utilities-system-monitor")
        if icon.isNull():
            icon = self.windowIcon()

        self.tray_icon = QSystemTrayIcon(icon, self)
        self.tray_icon.setToolTip("Honeypot / SIEM Dashboard")

        menu = QMenu()
        show_action = menu.addAction("Show dashboard")
        show_action.triggered.connect(self._show_and_raise)
        quit_action = menu.addAction("Quit")
        quit_action.triggered.connect(self.close)
        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self._on_tray_activated)

        self.tray_icon.show()

    def _on_tray_activated(self, reason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._show_and_raise()

    def _show_and_raise(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _notify_new_problems(self, results: dict) -> None:
        if not self.tray_icon or not self.state.tray_notifications_enabled:
            self._last_status = self._classify_all(results)
            return

        current = self._classify_all(results)
        for key, status in current.items():
            if status in _NOTIFY_ON_STATUSES and self._last_status.get(key) != status:
                target_key, service = key
                label = "unhealthy" if status == "unhealthy" else "exited with an error"
                self.tray_icon.showMessage(
                    "Container problem",
                    f"{service} ({target_key}) is {label}",
                    QSystemTrayIcon.MessageIcon.Warning,
                    8000,
                )
        self._last_status = current

    @staticmethod
    def _classify_all(results: dict) -> dict[tuple[str, str], str]:
        classified = {}
        for target_key, containers in results.items():
            for container in containers:
                service = container.get("Service")
                if service:
                    classified[(target_key, service)] = classify(container)
        return classified

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

    # ---- keyboard shortcuts ----

    def _build_shortcuts(self) -> None:
        # Ctrl+1..9: jump straight to the Nth page in the sidebar.
        for i, page_id in enumerate(PAGES[:9], start=1):
            shortcut = QShortcut(QKeySequence(f"Ctrl+{i}"), self)
            shortcut.activated.connect(lambda pid=page_id: self.nav_list.setCurrentRow(PAGES.index(pid)))

        # Ctrl+R: refresh whatever the current page can meaningfully
        # refresh on demand -- an embedded browser reload, an immediate
        # re-search, Redis's own Refresh button. Services/Health are
        # poll-driven already (a few seconds' staleness at most) so
        # there's no separate "refresh now" plumbing for those.
        refresh_shortcut = QShortcut(QKeySequence("Ctrl+R"), self)
        refresh_shortcut.activated.connect(self._on_refresh_shortcut)

        # Ctrl+F: jump to and focus the Log Search page's search box --
        # the one "find" surface in this app, so Ctrl+F behaves the way
        # it's expected to everywhere else.
        find_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        find_shortcut.activated.connect(self._on_find_shortcut)

    def _on_refresh_shortcut(self) -> None:
        current = self.stack.currentWidget()
        if current is self.kibana_page:
            current.browser.view.reload()
        elif current is self.exploits_page:
            current.browser.view.reload()
        elif current is self.log_search_page:
            current.run_search()
        elif current is self.redis_page:
            current.refresh()
        elif current is self.backups_page:
            current.refresh()
        elif current is self.certs_page and hasattr(current, "refresh"):
            current.refresh()

    def _on_find_shortcut(self) -> None:
        self.nav_list.setCurrentRow(PAGES.index("log_search"))
        self.log_search_page.focus_search_box()

    # ---- menu ----

    def _rerun_wizard(self) -> None:
        wizard = SetupWizard(self.state, self)
        wizard.exec()
        # Settings page holds its own EnvFile/RemoteConfigWidget instances
        # loaded at construction time -- rebuild it so it reflects whatever
        # the wizard just wrote, instead of showing stale pre-wizard values.
        self._reload_settings_page()
        self.services_page.rebuild_panels()
        self.redis_page.rebuild_targets()
        self.backups_page.rebuild_targets()
        self.exploits_page.rebuild_targets()
        self.log_search_page.rebuild_targets()
        self.security_feed.start(self._edge_target())

    def _reload_settings_page(self) -> None:
        index = self.stack.indexOf(self.settings_page)
        self.stack.removeWidget(self.settings_page)
        self.settings_page.deleteLater()
        self.settings_page = SettingsPage(self.state, self._on_remote_settings_changed, self.set_poll_interval)
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
        if self.services_page.any_mutating_action_running():
            reply = QMessageBox.warning(
                self, "Command still running",
                "A docker compose command (start/restart/stop/purge) is "
                "still running for at least one target. Closing now will "
                "kill it mid-operation.\n\nClose anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

        data = bytes(self.saveGeometry())
        self.state.window_geometry_b64 = base64.b64encode(data).decode("ascii")
        self.state.save()
        self.poller.stop()
        self.poller.wait(2000)
        self.security_feed.stop()
        if self.tray_icon:
            self.tray_icon.hide()
        super().closeEvent(event)
