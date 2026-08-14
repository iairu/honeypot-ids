"""Redis page: every key in session_store (the edge project's Redis --
sessions, threat_ips, suricata_alerts, ...) as a table (type/ttl/size,
click a row to see its full value) plus a bar chart of current threat_ips
scores by IP. Local or remote edge target, selectable via a dropdown --
mirrors the Services page's per-target model, just scoped to the one
project Redis actually belongs to."""
from __future__ import annotations

from PyQt6.QtCharts import QBarCategoryAxis, QBarSeries, QBarSet, QChart, QChartView, QValueAxis
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPainter
from PyQt6.QtWidgets import (
    QComboBox, QHBoxLayout, QHeaderView, QLabel, QMessageBox, QPlainTextEdit,
    QPushButton, QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.docker_ctl import Target, targets_for
from core.redis_inspect import (
    RedisInspectError, RedisKeyInfo, dbsize, flush_all, get_threat_scores, get_value, list_keys,
)
from core.state import AppState, RemoteConfig
from ui.process_runner import LogPanel


class RedisPage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self._targets: list[Target] = []
        self._keys: list[RedisKeyInfo] = []

        layout = QVBoxLayout(self)

        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Target:"))
        self.target_combo = QComboBox()
        toolbar.addWidget(self.target_combo)
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        toolbar.addWidget(self.refresh_btn)
        self.dbsize_label = QLabel("")
        toolbar.addWidget(self.dbsize_label)
        toolbar.addStretch()
        self.reset_btn = QPushButton("Reset Redis KV store…")
        self.reset_btn.setStyleSheet("QPushButton { color: #d9534f; }")
        self.reset_btn.clicked.connect(self._reset)
        toolbar.addWidget(self.reset_btn)
        layout.addLayout(toolbar)

        self.error_banner = QLabel("")
        self.error_banner.setWordWrap(True)
        self.error_banner.setStyleSheet(
            "background-color: #d9534f; color: white; padding: 6px; border-radius: 4px;"
        )
        self.error_banner.setVisible(False)
        layout.addWidget(self.error_banner)

        # Only ever shows output for the Reset action's reverse_proxy
        # restart (see _reset()) -- kept compact and out of the way the
        # rest of the time, but visible progress feedback matters here
        # since that restart alone can take over a minute (nginx's
        # graceful shutdown waits out in-flight keepalive connections --
        # same as ExploitsPage's "Unpoison host IP" restart).
        self.action_log = LogPanel(show_stop_button=False)
        self.action_log.setMaximumHeight(120)
        self.action_log.finished.connect(self._on_reset_restart_finished)
        layout.addWidget(self.action_log)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter, stretch=1)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Key", "Type", "TTL", "Size"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        splitter.addWidget(self.table)

        right = QSplitter(Qt.Orientation.Vertical)
        self.value_view = QPlainTextEdit(readOnly=True)
        self.value_view.setPlaceholderText("Select a key to see its value.")
        self.value_view.setStyleSheet(
            "QPlainTextEdit { font-family: monospace; font-size: 11px; }"
        )
        right.addWidget(self.value_view)

        self.chart_view = QChartView()
        self.chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.chart_view.setMinimumHeight(220)
        right.addWidget(self.chart_view)
        splitter.addWidget(right)
        splitter.setSizes([500, 500])

        self.rebuild_targets()
        self.target_combo.currentIndexChanged.connect(self.refresh)
        self.refresh()

    def showEvent(self, event) -> None:
        """Refreshes the key list/chart the moment this page becomes
        visible -- session_store's keys (sessions, threat_ips, rate
        limits...) change continuously from live traffic whether or not
        this page is open, so without this, switching back to it could
        show a listing that's stale (or still showing a since-resolved
        "unreachable" error banner). refresh() only re-populates the
        table/chart/error banner -- the target dropdown selection is
        untouched."""
        super().showEvent(event)
        self.refresh()

    def rebuild_targets(self) -> None:
        """Call when remote settings change (Settings page) -- rebuilds the
        target dropdown without necessarily changing the current
        selection's meaning if it still exists."""
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        self._targets = targets_for("edge", self.state.remote_edge, self.state.remote_siem)
        for t in self._targets:
            self.target_combo.addItem(t.label)
        self.target_combo.blockSignals(False)

    def _current_target(self) -> Target | None:
        idx = self.target_combo.currentIndex()
        if 0 <= idx < len(self._targets):
            return self._targets[idx]
        return None

    def _current_remote(self) -> RemoteConfig | None:
        target = self._current_target()
        return target.remote if target else None

    def _reset(self) -> None:
        target = self._current_target()
        if target is None:
            return
        reply = QMessageBox.warning(
            self, "Confirm Redis reset",
            "This wipes EVERY key in session_store's Redis (FLUSHALL) -- "
            "including attacker IP classification/reputation (threat_ips, "
            "built up from Suricata/admin/vulnerability/AbuseIPDB detections) "
            "and all active sessions (every visitor, including yourself, will "
            "be logged out and re-scored from scratch on their next request). "
            "Rate limits and sticky honeypot pool assignments are cleared too. "
            "reverse_proxy is then restarted automatically, since "
            "threat_analyzer.lua's hot-path IP-reputation check reads an "
            "in-memory copy of threat_ips that FLUSHALL alone doesn't touch "
            "-- without the restart, stale scores would keep being applied "
            "despite Redis itself being empty. This cannot be undone. "
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            flush_all(target.remote)
        except RedisInspectError as e:
            QMessageBox.warning(self, "Reset failed", str(e))
            return
        self.refresh()

        argv, cwd = target.build("restart", "reverse_proxy")
        self.action_log.run(argv, cwd)

    def _on_reset_restart_finished(self, exit_code: int) -> None:
        if exit_code == 0:
            self.refresh()

    def refresh(self) -> None:
        remote = self._current_remote()
        try:
            self._keys = list_keys(remote)
            size = dbsize(remote)
            error = None
        except RedisInspectError as e:
            self._keys = []
            size = 0
            error = str(e)

        if error:
            self.dbsize_label.setText("unreachable")
            self.dbsize_label.setStyleSheet("color: #d9534f;")
            self.error_banner.setText(f"⚠ session_store (Redis) unreachable: {error}")
            self.error_banner.setVisible(True)
        else:
            self.dbsize_label.setText(f"{size} keys")
            self.dbsize_label.setStyleSheet("")
            self.error_banner.setVisible(False)

        self.table.setRowCount(len(self._keys))
        for row, info in enumerate(self._keys):
            self.table.setItem(row, 0, QTableWidgetItem(info.name))
            self.table.setItem(row, 1, QTableWidgetItem(info.type))
            ttl_text = "no expiry" if info.ttl < 0 else f"{info.ttl}s"
            self.table.setItem(row, 2, QTableWidgetItem(ttl_text))
            self.table.setItem(row, 3, QTableWidgetItem(str(info.size)))
        self.value_view.clear()

        self._refresh_chart(remote)

    def _on_row_selected(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        if row >= len(self._keys):
            return
        info = self._keys[row]
        remote = self._current_remote()
        try:
            value = get_value(remote, info.name, info.type)
        except RedisInspectError as e:
            value = f"(error reading value: {e})"
        self.value_view.setPlainText(value)

    def _refresh_chart(self, remote: RemoteConfig | None) -> None:
        try:
            scores = get_threat_scores(remote)
        except RedisInspectError:
            scores = {}

        chart = QChart()
        if scores:
            # raw_score, not the decayed score threat_analyzer.lua actually
            # applies per-request -- see core/redis_inspect.py's
            # get_threat_scores() docstring.
            chart.setTitle("threat_ips raw_score by IP")
            bar_set = QBarSet("raw_score")
            ips = list(scores.keys())
            bar_set.append([scores[ip] for ip in ips])
            series = QBarSeries()
            series.append(bar_set)
            chart.addSeries(series)

            axis_x = QBarCategoryAxis()
            axis_x.append(ips)
            chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
            series.attachAxis(axis_x)

            axis_y = QValueAxis()
            axis_y.setRange(0, 100)
            chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
            series.attachAxis(axis_y)
            chart.legend().hide()
        else:
            chart.setTitle("threat_ips raw_score by IP -- no data yet")

        self.chart_view.setChart(chart)
