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
    QComboBox, QHBoxLayout, QHeaderView, QLabel, QPlainTextEdit,
    QPushButton, QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.docker_ctl import Target, targets_for
from core.redis_inspect import RedisInspectError, RedisKeyInfo, dbsize, get_threat_scores, get_value, list_keys
from core.state import AppState, RemoteConfig


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
        layout.addLayout(toolbar)

        self.error_banner = QLabel("")
        self.error_banner.setWordWrap(True)
        self.error_banner.setStyleSheet(
            "background-color: #d9534f; color: white; padding: 6px; border-radius: 4px;"
        )
        self.error_banner.setVisible(False)
        layout.addWidget(self.error_banner)

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

    def _current_remote(self) -> RemoteConfig | None:
        idx = self.target_combo.currentIndex()
        if 0 <= idx < len(self._targets):
            return self._targets[idx].remote
        return None

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
            chart.setTitle("threat_ips scores by IP")
            bar_set = QBarSet("Score")
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
            chart.setTitle("threat_ips scores by IP -- no data yet")

        self.chart_view.setChart(chart)
