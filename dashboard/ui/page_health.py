"""Health page: the cross-referenced service diagram, plus a details
panel for whatever node is selected (status detail, Restart, View Logs,
Open Web UI, Open Shell). The diagram's own nodes additionally carry a
quick "export logs to a file" icon (see ui/health_diagram.py) handled here
via export_logs_requested."""
from __future__ import annotations

import html
import re
from datetime import datetime, timedelta, timezone

from PyQt6.QtCore import QProcess, QTimer, QUrl, Qt
from PyQt6.QtGui import QColor, QDesktopServices
from PyQt6.QtWidgets import (
    QGroupBox, QHBoxLayout, QLabel, QMessageBox, QProgressBar, QPushButton,
    QSplitter, QVBoxLayout, QWidget,
)

from core.content_sync_status import parse_content_sync_log
from core.docker_ctl import PROJECT_LABELS
from core.shell_ctl import build_shell_command
from core.web_links import build_url, web_ui_for
from ui.error_monitor import ErrorLogMonitor, is_error_log_line
from ui.flow_layout import FlowLayout
from ui.health_diagram import (
    HealthDiagram, STATUS_COLORS, classify, is_ready, status_detail,
)
from ui.log_export import LogExporter
from ui.process_runner import LogPanel

CONTENT_SYNC_SERVICE = "honeypot_content_sync"

# Explicit, theme-INDEPENDENT progress-bar text/groove colors -- same fix,
# same reasoning, as page_services.py's own _PROGRESS_BASE_CSS (its own
# comment has the full rationale): the default/problem chunk colors below
# don't change with the app's light/dark/high-contrast theme, so the text
# drawn over them can't just inherit whatever the current QPalette's
# WindowText happens to be without risking poor contrast in some themes.
_PROGRESS_BASE_CSS = "QProgressBar { background-color: #3a3a3a; color: #ffffff; font-weight: bold; border-radius: 3px; }"


def _progress_chunk_css(color: str) -> str:
    return _PROGRESS_BASE_CSS + f"QProgressBar::chunk {{ background-color: {color}; border-radius: 3px; }}"

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

# How many consecutive polls a target is allowed to come back with zero
# containers before its group is actually redrawn as empty -- see
# HealthPage._debounce_empty().
_EMPTY_GRACE_POLLS = 2

# `docker compose ps --format json`'s own CreatedAt field is Go's default
# time.Time String() format, e.g. "2026-08-13 18:44:49 +0200 CEST" -- only
# the date/time/UTC-offset prefix is parsed; the trailing zone
# abbreviation ("CEST") is redundant once the numeric offset is known, and
# Python's %Z can't reliably parse arbitrary abbreviations for strptime
# anyway.
_CREATED_AT_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ([+-]\d{4})")


def _parse_created_at(value: str) -> datetime | None:
    if not value:
        return None
    m = _CREATED_AT_RE.match(value)
    if not m:
        return None
    try:
        return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        return None


def _format_duration(delta: timedelta) -> str:
    total = max(int(delta.total_seconds()), 0)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


class LegendWidget(QWidget):
    """Status-color key for the diagram below. Uses FlowLayout (not a plain
    QHBoxLayout) so entries wrap onto additional rows instead of forcing
    the whole page -- and the window -- wider to fit every entry on one
    line; confirmed live a QHBoxLayout here just clipped/overflowed at
    anything narrower than a very wide window."""

    def __init__(self, parent=None):
        super().__init__(parent)
        flow = FlowLayout(margin=0, h_spacing=16, v_spacing=6)
        # Kept terse on purpose, matching every other entry's style -- a
        # widget can never shrink narrower than its layout's reported
        # minimum size, and FlowLayout's minimum is the width of its
        # single WIDEST entry (not a sum), so one long sentence here would
        # silently put a floor under how narrow the whole legend -- and
        # the window containing it -- could ever actually get, defeating
        # the point of wrapping at all. Confirmed live: an earlier full-
        # sentence "created" entry alone forced a ~520px floor. Full
        # context lives in the tooltip instead.
        labels = {
            "healthy": "Up, healthy",
            "running": "Up (no healthcheck)",
            "unhealthy": "Up, unhealthy",
            "exited_ok": "Exited OK (code 0)",
            "exited_bad": "Exited with error",
            "created": "Created (never started)",
            "down": "Down / not created",
        }
        tooltips = {
            "created": "A prior Start/Restart got interrupted partway through -- click Start again.",
        }
        for key, text in labels.items():
            flow.addWidget(self._entry(text, swatch_color=STATUS_COLORS[key], tooltip=tooltips.get(key)))

        flow.addWidget(self._entry(
            "Contains \"error\"", badge_text="!3",
            tooltip="Bottom-right badge on a node: at least one log line for that service contains the word \"error\".",
        ))

        self.setLayout(flow)

    @staticmethod
    def _entry(
        text: str, swatch_color: QColor | None = None, badge_text: str | None = None,
        tooltip: str | None = None,
    ) -> QWidget:
        """One legend item (color swatch or error badge, plus its label)
        as a single widget -- FlowLayout wraps whole widgets onto a new
        row, so bundling each swatch with its own label here is what keeps
        the two from ever being split apart across a wrap."""
        entry = QWidget()
        if tooltip:
            entry.setToolTip(tooltip)
        row = QHBoxLayout(entry)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(4)
        if swatch_color is not None:
            swatch = QLabel("  ")
            swatch.setStyleSheet(f"background-color: {swatch_color.name()}; border-radius: 3px;")
            swatch.setFixedSize(16, 16)
            row.addWidget(swatch)
        if badge_text is not None:
            badge = QLabel(badge_text)
            badge.setStyleSheet(
                "background-color: #d9302c; color: white; font-weight: bold; "
                "font-size: 10px; border-radius: 3px; padding: 1px 3px;"
            )
            row.addWidget(badge)
        row.addWidget(QLabel(text))
        return entry


class HealthPage(QWidget):
    def __init__(self, get_targets, error_monitor: ErrorLogMonitor | None = None, parent=None):
        super().__init__(parent)
        self._get_targets = get_targets
        self._last_results: dict[str, list[dict]] = {}
        self._targets_by_key: dict[str, object] = {}
        # How many consecutive polls in a row a target has come back empty
        # -- see _debounce_empty().
        self._empty_streak: dict[str, int] = {}
        # project ("edge"/"siem") -> earliest CreatedAt among that
        # project's currently-running containers, across local+remote
        # targets combined -- see _update_uptimes()/_refresh_uptime_labels().
        self._project_started: dict[str, datetime] = {}

        layout = QVBoxLayout(self)

        layout.addWidget(LegendWidget())

        uptime_row = QHBoxLayout()
        self._uptime_labels: dict[str, QLabel] = {}
        for project in ("edge", "siem"):
            lbl = QLabel(f"{PROJECT_LABELS[project]} uptime: —")
            lbl.setStyleSheet("color: #888888;")
            self._uptime_labels[project] = lbl
            uptime_row.addWidget(lbl)
            uptime_row.addSpacing(24)
        uptime_row.addStretch()
        layout.addLayout(uptime_row)

        # Ticks every second so the displayed uptime keeps counting up
        # smoothly between polls, not just once per poll interval -- the
        # underlying start times themselves only change on a real poll
        # (_update_uptimes(), called from apply_status()).
        self._uptime_timer = QTimer(self)
        self._uptime_timer.timeout.connect(self._refresh_uptime_labels)
        self._uptime_timer.start(1000)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter, stretch=1)

        self.diagram = HealthDiagram(error_monitor)
        self.diagram.node_selected.connect(self._on_node_selected)
        self.diagram.error_badge_selected.connect(self._on_error_badge_selected)
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

    def showEvent(self, event) -> None:
        """Forces one fresh `docker compose ps` per target the moment this
        page becomes visible, rather than leaving the diagram showing
        whatever the background StatusPoller (ui/main_window.py) last
        fetched -- that poller keeps running regardless of which page is
        open, but at up to a 300s interval (Settings), so without this the
        diagram could be showing up-to-5-minutes-stale data for as long as
        it takes the next tick to land. Same pattern as ExploitsPage's own
        showEvent()-driven reachability check. Selection/log-tail/restart-
        progress state is untouched -- apply_status() only ever rebuilds
        the diagram and refreshes the (still-selected) detail panel."""
        super().showEvent(event)
        self.apply_status({t.key: t.ps() for t in self._get_targets()})

    def apply_status(self, results: dict[str, list[dict]]) -> None:
        targets = self._get_targets()
        self._targets_by_key = {t.key: t for t in targets}
        results = self._debounce_empty(results, targets)
        self._last_results = results
        self.diagram.rebuild(targets, results)
        if self._selected:
            self._refresh_detail_label()
        self._update_restart_progress()
        self._update_uptimes(targets, results)

    def _debounce_empty(
        self, results: dict[str, list[dict]], targets,
    ) -> dict[str, list[dict]]:
        """A poll that comes back empty for a target that had real
        containers a moment ago is treated as a transient blip, not
        "everything's gone", for up to _EMPTY_GRACE_POLLS consecutive
        polls -- confirmed live that a `docker compose ps` invocation
        racing an in-flight Start/Restart for the same project (containers
        passing through the "created" state) can transiently come back
        empty, which without this wiped the whole diagram group to a
        "(no containers found)" placeholder for a poll or two before
        self-correcting -- a confusing flicker for something that was
        never actually down. A target that's genuinely stopped still
        correctly goes empty once the grace period elapses."""
        display: dict[str, list[dict]] = {}
        for target in targets:
            containers = results.get(target.key, [])
            if containers:
                self._empty_streak[target.key] = 0
                display[target.key] = containers
                continue
            streak = self._empty_streak.get(target.key, 0) + 1
            self._empty_streak[target.key] = streak
            prior = self._last_results.get(target.key)
            display[target.key] = prior if prior and streak <= _EMPTY_GRACE_POLLS else containers
        return display

    def _update_uptimes(self, targets, results: dict[str, list[dict]]) -> None:
        """One shared uptime per PROJECT (ids/siem), not per target --
        local and remote targets for the same project are combined,
        taking the earliest CreatedAt among all their currently-running
        containers. Recomputed every real poll; _refresh_uptime_labels()
        (the 1s QTimer) does the actual continuous counting-up in
        between."""
        earliest: dict[str, datetime] = {}
        for target in targets:
            for container in results.get(target.key, []):
                if container.get("State") != "running":
                    continue
                created = _parse_created_at(container.get("CreatedAt", ""))
                if created is None:
                    continue
                if target.project not in earliest or created < earliest[target.project]:
                    earliest[target.project] = created
        self._project_started = earliest
        self._refresh_uptime_labels()

    def _refresh_uptime_labels(self) -> None:
        now = datetime.now(timezone.utc)
        for project, label in self._uptime_labels.items():
            started = self._project_started.get(project)
            if started is None:
                label.setText(f"{PROJECT_LABELS[project]} uptime: —")
            else:
                label.setText(f"{PROJECT_LABELS[project]} uptime: {_format_duration(now - started)}")

    def _selected_container(self) -> dict | None:
        if not self._selected:
            return None
        target_key, service = self._selected
        containers = self._last_results.get(target_key, [])
        return next((c for c in containers if c.get("Service") == service), None)

    def _select_node_common(self, target_key: str, service: str) -> None:
        """Shared setup for both ways a node can become selected -- clicking
        the rest of its rectangle (_on_node_selected) or its error badge
        (_on_error_badge_selected). Only what happens to the log panel
        afterward differs between the two."""
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

    def _on_node_selected(self, target_key: str, service: str) -> None:
        self._select_node_common(target_key, service)
        # Auto-start the live tail immediately -- no need to click "View
        # logs" separately just to see what a newly-selected node is doing.
        self._view_logs_selected()

    def _on_error_badge_selected(self, target_key: str, service: str) -> None:
        self._select_node_common(target_key, service)
        self._view_error_logs_selected()

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
        self.restart_progress.setStyleSheet(_PROGRESS_BASE_CSS)
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
            self.restart_progress.setStyleSheet(_progress_chunk_css("#d9534f"))

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
            self.restart_progress.setStyleSheet(_progress_chunk_css("#d9534f"))
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

    def _view_error_logs_selected(self) -> None:
        """Similar to _view_logs_selected(), but the panel only shows
        lines that would increment this node's error badge -- triggered
        by clicking the badge itself. Clicking anywhere else on the node,
        or View logs, goes through _view_logs_selected() instead and
        always shows everything, unfiltered.

        Deliberately `--tail=all`, not `--tail=300` like the plain view:
        the whole point of clicking the badge is "show me every error
        this service has logged", and a service whose error lines are a
        small fraction of its total chatty output could easily have all
        of them pushed out of a 300-line window by unrelated noise --
        capping history here would silently hide exactly what this view
        exists to surface. The client-side filter still means only the
        (usually far smaller) matching lines actually get rendered.
        """
        if not self._selected:
            return
        target_key, service = self._selected
        target = self._targets_by_key.get(target_key)
        if target is None:
            return
        argv, cwd = target.build("logs", "--tail=all", "-f", service)
        self.log_panel.run(argv, cwd, line_filter=is_error_log_line)
        self.log_panel.append(
            f'(showing every line containing "error" for {service}, full history -- '
            "click elsewhere on the node, or View logs, for the full recent tail)\n\n"
        )

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
