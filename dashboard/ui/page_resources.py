"""Resources page: per-container live resource usage (CPU, memory, PIDs,
net/block I/O and on-disk log size) shown htop-style in a table, plus a
CPU% / memory% history graph for the selected container.

A background _StatsWorker polls `docker stats` (+ compose ps, + a periodic
log-size sweep) for the selected target only while this page is visible, so it
costs nothing when you're on another page. See core/resource_stats.py.
"""
from __future__ import annotations

import time
from collections import deque

from PyQt6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis
from PyQt6.QtCore import QPointF, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import (
    QComboBox, QHBoxLayout, QHeaderView, QLabel, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from core import resource_stats as rs
from core.resource_stats import ContainerResource, human_bytes
from ui import theme

# History depth for the graph: HISTORY_POINTS samples * POLL_SECONDS apart.
POLL_SECONDS = 2.0
LOG_EVERY_TICKS = 7           # refresh (heavier) log-size sweep every ~14s
HISTORY_POINTS = 150          # ~5 minutes at 2s

_COLUMNS = ["Service", "State", "CPU %", "Memory", "Mem %", "Net I/O", "Block I/O", "PIDs", "Log size"]


def _load_color(percent: float, med: float, high: float) -> QColor | None:
    if percent >= high:
        return QColor("#c0392b")
    if percent >= med:
        return QColor("#d68910")
    return None


class _StatsWorker(QThread):
    """Polls one target's per-container stats in the background."""
    sample_ready = pyqtSignal(list)   # list[ContainerResource]

    def __init__(self, target, parent=None):
        super().__init__(parent)
        self._target = target
        self._stop = False
        self._log_cache: dict[str, int] = {}

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        tick = 0
        while not self._stop:
            try:
                live = rs.collect_live(self._target)
                if tick % LOG_EVERY_TICKS == 0:
                    self._log_cache = rs.collect_log_sizes(self._target)
                rs.merge_log_sizes(live, self._log_cache)
            except Exception:  # noqa: BLE001 -- never let a transient docker hiccup kill the poll loop
                live = []
            if self._stop:
                break
            self.sample_ready.emit(live)
            tick += 1
            # Sleep in slices so stop() is responsive.
            for _ in range(int(POLL_SECONDS * 10)):
                if self._stop:
                    break
                self.msleep(100)


class ResourcesPage(QWidget):
    def __init__(self, get_targets, parent=None):
        super().__init__(parent)
        self._get_targets = get_targets
        self._worker: _StatsWorker | None = None
        # service -> deque[(t, cpu_percent, mem_percent)]
        self._history: dict[str, deque] = {}
        self._row_for_service: dict[str, int] = {}
        self._selected_service: str | None = None

        layout = QVBoxLayout(self)

        # --- top bar: target selector + summary ---
        top = QHBoxLayout()
        top.addWidget(QLabel("Target:"))
        self.target_combo = QComboBox()
        self._targets = list(self._get_targets())
        for t in self._targets:
            self.target_combo.addItem(t.label, t)
        self.target_combo.currentIndexChanged.connect(self._on_target_changed)
        top.addWidget(self.target_combo)
        top.addSpacing(16)
        self.summary = QLabel("")
        self.summary.setStyleSheet("color: #888888;")
        top.addWidget(self.summary)
        top.addStretch()
        layout.addLayout(top)

        # --- htop-like table ---
        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in range(1, len(_COLUMNS)):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        layout.addWidget(self.table, stretch=3)

        # --- CPU% / Mem% history chart for the selected container ---
        self.chart_title = QLabel("Select a container to graph its CPU / memory history.")
        self.chart_title.setStyleSheet("color: #888888;")
        layout.addWidget(self.chart_title)

        self.cpu_series = QLineSeries()
        self.cpu_series.setName("CPU %")
        self.mem_series = QLineSeries()
        self.mem_series.setName("Memory %")
        self._chart = QChart()
        self._chart.addSeries(self.cpu_series)
        self._chart.addSeries(self.mem_series)
        self._chart.legend().setVisible(True)
        self._chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)

        self._axis_x = QValueAxis()
        self._axis_x.setTitleText("seconds ago")
        self._axis_x.setRange(-HISTORY_POINTS * POLL_SECONDS, 0)
        self._axis_y = QValueAxis()
        self._axis_y.setTitleText("%")
        self._axis_y.setRange(0, 100)
        self._chart.addAxis(self._axis_x, Qt.AlignmentFlag.AlignBottom)
        self._chart.addAxis(self._axis_y, Qt.AlignmentFlag.AlignLeft)
        for s in (self.cpu_series, self.mem_series):
            s.attachAxis(self._axis_x)
            s.attachAxis(self._axis_y)

        chart_view = QChartView(self._chart)
        chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        chart_view.setMinimumHeight(220)
        layout.addWidget(chart_view, stretch=2)

    # ---- lifecycle: poll only while visible ----

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._start_worker()

    def hideEvent(self, event) -> None:
        super().hideEvent(event)
        self._stop_worker()

    def rebuild_targets(self) -> None:
        """Called when remote settings change -- refresh the target list."""
        current = self.target_combo.currentData()
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        self._targets = list(self._get_targets())
        for t in self._targets:
            self.target_combo.addItem(t.label, t)
        # Re-select the same target key if it still exists.
        idx = 0
        for i, t in enumerate(self._targets):
            if current is not None and t.key == current.key:
                idx = i
                break
        self.target_combo.setCurrentIndex(idx)
        self.target_combo.blockSignals(False)
        if self.isVisible():
            self._restart_worker()

    def _current_target(self):
        return self.target_combo.currentData()

    def _on_target_changed(self, _index: int) -> None:
        # New target: drop history/table and restart the poller.
        self._history.clear()
        self._row_for_service.clear()
        self._selected_service = None
        self.table.setRowCount(0)
        self.cpu_series.clear()
        self.mem_series.clear()
        if self.isVisible():
            self._restart_worker()

    def _start_worker(self) -> None:
        if self._worker is not None:
            return
        target = self._current_target()
        if target is None:
            return
        self._worker = _StatsWorker(target)
        self._worker.sample_ready.connect(self._on_sample)
        self._worker.start()

    def _stop_worker(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self._worker.wait(3000)
            self._worker.deleteLater()
            self._worker = None

    def _restart_worker(self) -> None:
        self._stop_worker()
        self._start_worker()

    # ---- sample handling ----

    def _on_sample(self, resources: list) -> None:
        now = time.monotonic()
        resources = sorted(resources, key=lambda r: r.service)

        # Update history buffers.
        for r in resources:
            buf = self._history.setdefault(r.service, deque(maxlen=HISTORY_POINTS))
            buf.append((now, r.cpu_percent, r.mem_percent))

        self._rebuild_table(resources)
        self._update_summary(resources)
        self._update_chart(now)

    def _rebuild_table(self, resources: list) -> None:
        # Stable row order (by service) so selection/scroll don't jump; update
        # cells in place, creating rows only when the set of services changes.
        services = [r.service for r in resources]
        if list(self._row_for_service.keys()) != services:
            self.table.setRowCount(len(resources))
            self._row_for_service = {r.service: i for i, r in enumerate(resources)}
            for i, r in enumerate(resources):
                self._set_row(i, r, fresh=True)
            self._reselect()
        else:
            for r in resources:
                self._set_row(self._row_for_service[r.service], r, fresh=False)

    def _set_row(self, row: int, r: ContainerResource, fresh: bool) -> None:
        running = r.running
        mem_txt = human_bytes(r.mem_used_bytes)
        if r.mem_limit_bytes:
            mem_txt += " / " + human_bytes(r.mem_limit_bytes)
        values = [
            r.service,
            r.state,
            f"{r.cpu_percent:.1f}" if running else "-",
            mem_txt if running else "-",
            f"{r.mem_percent:.1f}" if running else "-",
            r.net_io if running else "-",
            r.block_io if running else "-",
            str(r.pids) if running else "-",
            human_bytes(r.log_bytes) if r.log_bytes else "-",
        ]
        cpu_color = _load_color(r.cpu_percent, 50, 100) if running else None
        mem_color = _load_color(r.mem_percent, 60, 85) if running else None
        for col, text in enumerate(values):
            item = self.table.item(row, col)
            if item is None or fresh:
                item = QTableWidgetItem(text)
                if col in (2, 4, 7):  # numeric columns right-aligned
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self.table.setItem(row, col, item)
            else:
                item.setText(text)
            if col == 2:
                item.setForeground(cpu_color if cpu_color else self.table.palette().text().color())
            elif col == 4:
                item.setForeground(mem_color if mem_color else self.table.palette().text().color())
            elif col == 1:
                item.setForeground(QColor("#888888") if not running else self.table.palette().text().color())

    def _update_summary(self, resources: list) -> None:
        running = [r for r in resources if r.running]
        total_cpu = sum(r.cpu_percent for r in running)
        total_mem = sum(r.mem_used_bytes for r in running)
        total_log = sum(r.log_bytes for r in resources)
        self.summary.setText(
            f"{len(running)}/{len(resources)} running   ·   "
            f"total CPU {total_cpu:.1f}%   ·   "
            f"total memory {human_bytes(total_mem)}   ·   "
            f"total logs {human_bytes(total_log)}"
        )

    # ---- selection + chart ----

    def _on_row_selected(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        item = self.table.item(row, 0)
        if item is not None:
            self._selected_service = item.text()
            self._update_chart(time.monotonic())

    def _reselect(self) -> None:
        if self._selected_service and self._selected_service in self._row_for_service:
            self.table.selectRow(self._row_for_service[self._selected_service])

    def _update_chart(self, now: float) -> None:
        svc = self._selected_service
        buf = self._history.get(svc) if svc else None
        if not svc or not buf:
            self.cpu_series.clear()
            self.mem_series.clear()
            self.chart_title.setText("Select a container to graph its CPU / memory history.")
            return
        self.chart_title.setText(f"CPU / memory history — {svc}")
        cpu_points = []
        mem_points = []
        max_cpu = 100.0
        for t, cpu, mem in buf:
            x = -(now - t)  # seconds ago (<= 0)
            cpu_points.append((x, cpu))
            mem_points.append((x, mem))
            max_cpu = max(max_cpu, cpu)
        self.cpu_series.replace([QPointF(x, y) for x, y in cpu_points])
        self.mem_series.replace([QPointF(x, y) for x, y in mem_points])
        self._axis_y.setRange(0, max_cpu * 1.1)
