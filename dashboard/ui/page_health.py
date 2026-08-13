"""Health page: the cross-referenced service diagram, plus a details
panel for whatever node is selected (status detail, Restart, View Logs,
Open Web UI, Open Shell). The diagram's own nodes additionally carry a
quick "export logs to a file" icon (see ui/health_diagram.py) handled here
via export_logs_requested."""
from __future__ import annotations

import html

from PyQt6.QtCore import QProcess, QUrl, Qt
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QGroupBox, QHBoxLayout, QLabel, QMessageBox, QProgressBar, QPushButton,
    QSplitter, QVBoxLayout, QWidget,
)

from core.content_sync_status import parse_content_sync_log
from core.shell_ctl import build_shell_command
from core.web_links import build_url, web_ui_for
from ui.health_diagram import (
    HealthDiagram, STATUS_COLORS, classify, is_ready, status_detail,
)
from ui.log_export import LogExporter
from ui.process_runner import LogPanel

CONTENT_SYNC_SERVICE = "honeypot_content_sync"

# Bound on how much of the live log tail we keep re-parsing on every
# chunk (see _on_log_line) -- a handful of lines per replication cycle
# (default every 300s) means this easily covers many hours of history
# without needing to grow unbounded for a panel that's only ever shown
# while this one node is selected.
_SYNC_LOG_BUFFER_MAX_CHARS = 20_000

_POOL_STATUS_COLORS = {
    "starting": "#3f9fd9",
    "complete": "#5cb85c",
    "failed": "#d9534f",
}


class LegendWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        labels = {
            "healthy": "Up, healthy",
            "running": "Up (no healthcheck)",
            "unhealthy": "Up, unhealthy",
            "exited_ok": "Exited OK (code 0)",
            "exited_bad": "Exited with error",
            "down": "Down / not created",
        }
        for key, text in labels.items():
            color = STATUS_COLORS[key]
            swatch = QLabel("  ")
            swatch.setStyleSheet(f"background-color: {color.name()}; border-radius: 3px;")
            swatch.setFixedSize(16, 16)
            layout.addWidget(swatch)
            lbl = QLabel(text)
            layout.addWidget(lbl)
            layout.addSpacing(12)
        layout.addStretch()


class HealthPage(QWidget):
    def __init__(self, get_targets, parent=None):
        super().__init__(parent)
        self._get_targets = get_targets
        self._last_results: dict[str, list[dict]] = {}
        self._targets_by_key: dict[str, object] = {}

        layout = QVBoxLayout(self)

        layout.addWidget(LegendWidget())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter, stretch=1)

        self.diagram = HealthDiagram()
        self.diagram.node_selected.connect(self._on_node_selected)
        self.diagram.export_logs_requested.connect(self._export_logs)
        splitter.addWidget(self.diagram)

        detail_panel = QGroupBox("Selected service")
        detail_layout = QVBoxLayout(detail_panel)
        self.detail_label = QLabel("Click a node to see details.")
        self.detail_label.setWordWrap(True)
        detail_layout.addWidget(self.detail_label)

        btn_row = QHBoxLayout()
        self.restart_btn = QPushButton("Restart")
        self.restart_btn.setEnabled(False)
        self.restart_btn.clicked.connect(self._restart_selected)
        self.logs_btn = QPushButton("View logs")
        self.logs_btn.setEnabled(False)
        self.logs_btn.clicked.connect(self._view_logs_selected)
        btn_row.addWidget(self.restart_btn)
        btn_row.addWidget(self.logs_btn)
        detail_layout.addLayout(btn_row)

        # Shown from the Restart click until the diagram reports this
        # container healthy/running again -- `docker compose restart`
        # itself returns almost immediately, well before a container with
        # a healthcheck actually becomes ready again, which is exactly the
        # gap this makes visible instead of leaving Restart looking like a
        # no-op.
        self.restart_progress = QProgressBar()
        self.restart_progress.setVisible(False)
        self.restart_progress.setTextVisible(True)
        detail_layout.addWidget(self.restart_progress)
        self._restarting = False

        btn_row2 = QHBoxLayout()
        self.web_ui_btn = QPushButton("Open web UI")
        self.web_ui_btn.setEnabled(False)
        self.web_ui_btn.clicked.connect(self._open_web_ui_selected)
        self.shell_btn = QPushButton("Open shell")
        self.shell_btn.setEnabled(False)
        self.shell_btn.clicked.connect(self._open_shell_selected)
        btn_row2.addWidget(self.web_ui_btn)
        btn_row2.addWidget(self.shell_btn)
        detail_layout.addLayout(btn_row2)

        # Only shown for honeypot_content_sync (see _on_node_selected) --
        # that service has no Docker healthcheck and writes no
        # host-readable state file, so "container running" alone can't
        # tell you whether a replication cycle is actually succeeding.
        # This parses that signal out of the very log tail already
        # streaming into log_panel below, rather than adding a second
        # docker-exec round trip.
        self.sync_activity_label = QLabel("")
        self.sync_activity_label.setWordWrap(True)
        self.sync_activity_label.setVisible(False)
        self.sync_activity_label.setStyleSheet(
            "QLabel { background-color: rgba(128, 128, 128, 30); padding: 6px; border-radius: 4px; }"
        )
        detail_layout.addWidget(self.sync_activity_label)
        self._sync_log_buffer = ""

        self.log_panel = LogPanel()
        self.log_panel.line_received.connect(self._on_log_line)
        self.log_panel.finished.connect(self._on_log_finished)
        detail_layout.addWidget(self.log_panel, stretch=1)
        self._pending_restart_service: str | None = None

        detail_panel.setMinimumWidth(320)
        splitter.addWidget(detail_panel)
        splitter.setSizes([700, 320])

        self._selected: tuple[str, str] | None = None
        self._log_exporter = LogExporter(self)

    def apply_status(self, results: dict[str, list[dict]]) -> None:
        self._last_results = results
        targets = self._get_targets()
        self._targets_by_key = {t.key: t for t in targets}
        self.diagram.rebuild(targets, results)
        if self._selected:
            self._refresh_detail_label()
        self._update_restart_progress()

    def _selected_container(self) -> dict | None:
        if not self._selected:
            return None
        target_key, service = self._selected
        containers = self._last_results.get(target_key, [])
        return next((c for c in containers if c.get("Service") == service), None)

    def _on_node_selected(self, target_key: str, service: str) -> None:
        self._selected = (target_key, service)
        self.restart_btn.setEnabled(True)
        self.logs_btn.setEnabled(True)
        # A restart in progress belongs to whatever node was selected when
        # it was started -- switching to a different node stops tracking
        # it here (the diagram's own node coloring still reflects it).
        self._restarting = False
        self._pending_restart_service = None
        self.restart_progress.setVisible(False)
        self._refresh_detail_label()

        self._sync_log_buffer = ""
        self.sync_activity_label.setVisible(service == CONTENT_SYNC_SERVICE)
        if service == CONTENT_SYNC_SERVICE:
            self.sync_activity_label.setText("Content sync activity: waiting for log output…")

        # Auto-start the live tail immediately -- no need to click "View
        # logs" separately just to see what a newly-selected node is doing.
        self._view_logs_selected()

    def _refresh_detail_label(self) -> None:
        target_key, service = self._selected
        container = self._selected_container()
        status = classify(container)
        detail = status_detail(container)
        target = self._targets_by_key.get(target_key)
        target_label = target.label if target else target_key
        self.detail_label.setText(
            f"<b>{service}</b><br>Target: {target_label}<br>Status: {status}<br>{detail}"
        )

        is_running = container is not None and container.get("State") == "running"
        project = target.project if target else None

        has_web_ui = project is not None and web_ui_for(project, service) is not None
        self.web_ui_btn.setEnabled(has_web_ui and is_running)

        self.shell_btn.setEnabled(is_running)

    def _restart_selected(self) -> None:
        if not self._selected:
            return
        target_key, service = self._selected
        target = self._targets_by_key.get(target_key)
        if target is None:
            return
        self._restarting = True
        self._pending_restart_service = service
        self.restart_progress.setRange(0, 0)  # indeterminate until the next status poll
        self.restart_progress.setFormat("Restarting…")
        self.restart_progress.setStyleSheet("")
        self.restart_progress.setVisible(True)
        argv, cwd = target.build("restart", service)
        self.log_panel.run(argv, cwd)

    def _update_restart_progress(self) -> None:
        if not self._restarting or not self._selected:
            return
        container = self._selected_container()
        if container is None:
            return  # container being recreated -- stay indeterminate
        if is_ready(container):
            self._restarting = False
            self.restart_progress.setVisible(False)
            return
        status = classify(container)
        if status in ("unhealthy", "exited_bad"):
            self.restart_progress.setFormat(f"Restarting… ({status})")
            self.restart_progress.setStyleSheet("QProgressBar::chunk { background-color: #d9534f; }")

    def _on_log_finished(self, exit_code: int) -> None:
        # Only the restart command itself is tracked here -- log_panel is
        # shared with the plain `logs -f` tail, whose own exit (e.g.
        # switching nodes) has nothing to do with a restart's success.
        service = self._pending_restart_service
        if service is None:
            return
        self._pending_restart_service = None
        if exit_code != 0 and self._restarting:
            self._restarting = False
            self.restart_progress.setFormat(f"Restart failed (exit {exit_code})")
            self.restart_progress.setRange(0, 1)
            self.restart_progress.setValue(1)
            self.restart_progress.setStyleSheet("QProgressBar::chunk { background-color: #d9534f; }")
        # Resume the live log tail now that the one-shot restart command
        # has finished, same as the Services page does for its own
        # up/restart/down commands.
        if self._selected and self._selected[1] == service:
            self._view_logs_selected()

    def _view_logs_selected(self) -> None:
        if not self._selected:
            return
        target_key, service = self._selected
        target = self._targets_by_key.get(target_key)
        if target is None:
            return
        argv, cwd = target.build("logs", "--tail=300", "-f", service)
        self.log_panel.run(argv, cwd)

    def _on_log_line(self, text: str) -> None:
        if not self._selected or self._selected[1] != CONTENT_SYNC_SERVICE:
            return
        self._sync_log_buffer = (self._sync_log_buffer + text)[-_SYNC_LOG_BUFFER_MAX_CHARS:]
        activity = parse_content_sync_log(self._sync_log_buffer)

        if not activity.per_pool and not activity.last_message:
            self.sync_activity_label.setText("Content sync activity: no log output parsed yet.")
            return

        lines = ["<b>Content sync activity</b> (parsed from the log tail below):"]
        for pool_num in (1, 2, 3):
            pool = activity.per_pool.get(pool_num)
            if pool is None:
                lines.append(f"Pool {pool_num}: no data yet")
            else:
                color = _POOL_STATUS_COLORS.get(pool.status, "#888888")
                lines.append(
                    f"Pool {pool_num}: <span style='color:{color};'>{pool.status}</span> @ {pool.timestamp}"
                )
        if activity.last_message:
            lines.append(
                f"Last log line ({activity.last_timestamp}): {html.escape(activity.last_message)}"
            )
        self.sync_activity_label.setText("<br>".join(lines))

    def _open_web_ui_selected(self) -> None:
        if not self._selected:
            return
        target_key, service = self._selected
        target = self._targets_by_key.get(target_key)
        if target is None:
            return
        host = target.remote.host if target.is_remote else "127.0.0.1"
        url = build_url(target.project, service, host)
        if url:
            QDesktopServices.openUrl(QUrl(url))

    def _export_logs(self, target_key: str, service: str) -> None:
        target = self._targets_by_key.get(target_key)
        if target is None:
            return
        self._log_exporter.export(target, target_key, service, service)

    def _open_shell_selected(self) -> None:
        if not self._selected:
            return
        target_key, service = self._selected
        target = self._targets_by_key.get(target_key)
        container = self._selected_container()
        if target is None or container is None:
            return

        container_name = container.get("Name") or container.get("Names") or service
        shell_cmd = build_shell_command(target, container_name)

        if shell_cmd.terminal_argv is None:
            QMessageBox.information(
                self, "No terminal emulator found",
                "Couldn't find a terminal emulator on this system to launch. "
                "Run this command yourself:\n\n" + " ".join(shell_cmd.argv),
            )
            return

        QProcess.startDetached(shell_cmd.terminal_argv[0], shell_cmd.terminal_argv[1:])
