"""Resources page: per-container live resource usage (CPU, memory, PIDs,
net/block I/O and on-disk log size) shown htop-style in a table, plus three
over-time graphs (CPU %, memory, log size), each with one coloured line per
container and a bold average line.

A background _StatsWorker polls `docker stats` (+ compose ps, + a periodic
log-size sweep) for the selected target only while this page is visible. It is
stopped WITHOUT blocking the GUI thread (the old code's worker.wait() froze the
UI while a `docker stats` call was in flight); the retired worker finishes its
current poll in the background and deletes itself. See core/resource_stats.py.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from PyQt6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis
from PyQt6.QtCore import QPointF, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QCursor, QPainter, QPen
from PyQt6.QtWidgets import (
    QComboBox, QHBoxLayout, QHeaderView, QLabel, QTableWidget,
    QTableWidgetItem, QTabWidget, QToolTip, QVBoxLayout, QWidget,
)

from core import resource_stats as rs
from core.resource_stats import ContainerResource, human_bytes

POLL_SECONDS = 2.0
LOG_EVERY_TICKS = 7           # heavier log-size sweep every ~14s
HISTORY_POINTS = 150          # ~5 minutes at 2s
_WINDOW_SECONDS = HISTORY_POINTS * POLL_SECONDS

_COLUMNS = ["Service", "State", "CPU %", "Memory", "Mem %", "Net I/O", "Block I/O", "PIDs", "Log size"]

# (key, tab title, y-axis title, value extractor -> float|None). Extractors
# return None when a container has no meaningful value for that metric this tick
# (e.g. a stopped container has no CPU/memory sample).
_METRICS = [
    ("cpu", "CPU %", "%", lambda r: r.cpu_percent if r.running else None),
    ("mem", "Memory (MiB)", "MiB", lambda r: r.mem_used_bytes / 1048576.0 if r.running else None),
    ("log", "Logs (KiB)", "KiB", lambda r: r.log_bytes / 1024.0 if r.log_bytes else None),
]


def _load_color(percent: float, med: float, high: float) -> QColor | None:
    if percent >= high:
        return QColor("#c0392b")
    if percent >= med:
        return QColor("#d68910")
    return None


def _series_color(index: int) -> QColor:
    # Golden-ratio hue spacing gives well-separated colours for many series.
    return QColor.fromHsvF((index * 0.61803398875) % 1.0, 0.62, 0.88)


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
            except Exception:  # noqa: BLE001 -- never let a docker hiccup kill the loop
                live = []
            if self._stop:
                break
            self.sample_ready.emit(live)
            tick += 1
            for _ in range(int(POLL_SECONDS * 10)):  # responsive to stop()
                if self._stop:
                    break
                self.msleep(100)


class _MetricChart(QWidget):
    """One over-time chart: a coloured line per service plus a bold average."""

    def __init__(self, y_title: str, parent=None):
        super().__init__(parent)
        self._series: dict[str, QLineSeries] = {}
        self._unit = y_title                       # "%", "MiB" or "KiB"
        self._labels: dict[str, str] = {}          # service -> full container name
        self._marker_series: dict[int, QLineSeries] = {}   # marker id -> vertical line
        self._marker_labels: dict = {}             # series -> exploit name (for hover)
        self._chart = QChart()
        self._chart.legend().setVisible(True)
        self._chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
        self._chart.setMargins(self._chart.margins())

        self._axis_x = QValueAxis()
        self._axis_x.setTitleText("seconds ago")
        self._axis_x.setRange(-_WINDOW_SECONDS, 0)
        self._axis_y = QValueAxis()
        self._axis_y.setTitleText(y_title)
        self._axis_y.setRange(0, 100)
        self._chart.addAxis(self._axis_x, Qt.AlignmentFlag.AlignBottom)
        self._chart.addAxis(self._axis_y, Qt.AlignmentFlag.AlignLeft)

        self._avg = QLineSeries()
        self._avg.setName("average")
        self._avg.hovered.connect(self._on_hovered)
        self._chart.addSeries(self._avg)
        self._avg.attachAxis(self._axis_x)
        self._avg.attachAxis(self._axis_y)
        pen = QPen(QColor("#111111"))
        pen.setWidth(3)
        self._avg.setPen(pen)

        view = QChartView(self._chart)
        view.setRenderHint(QPainter.RenderHint.Antialiasing)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(view)

    def _ensure_series(self, service: str, color: QColor) -> QLineSeries:
        s = self._series.get(service)
        if s is None:
            s = QLineSeries()
            s.setName(service)
            s.setPen(QPen(color, 1))
            s.hovered.connect(self._on_hovered)
            self._chart.addSeries(s)
            s.attachAxis(self._axis_x)
            s.attachAxis(self._axis_y)
            # Keep the average series drawn on top of the per-service lines.
            self._chart.removeSeries(self._avg)
            self._chart.addSeries(self._avg)
            self._avg.attachAxis(self._axis_x)
            self._avg.attachAxis(self._axis_y)
            self._series[service] = s
        return s

    def _on_hovered(self, point, state: bool) -> None:
        """Tooltip with the full container name + value when the cursor is on a
        line; also thicken that line so it's obvious which one you're reading.
        Exploit-marker lines show the exploit name instead."""
        series = self.sender()
        if series is None:
            return
        if series in self._marker_labels:
            if state:
                QToolTip.showText(QCursor.pos(), "Exploit: " + self._marker_labels[series])
            else:
                QToolTip.hideText()
            return
        pen = series.pen()
        is_avg = series is self._avg
        if state:
            pen.setWidth(4 if not is_avg else 5)
            series.setPen(pen)
            if is_avg:
                name = "average (all containers)"
            else:
                svc = series.name()
                name = self._labels.get(svc, svc)
            QToolTip.showText(QCursor.pos(), f"{name}\n{point.y():.1f} {self._unit}")
        else:
            pen.setWidth(3 if is_avg else 1)
            series.setPen(pen)
            QToolTip.hideText()

    def _draw_markers(self, markers: list, now: float, y_top: float) -> None:
        """Draw a vertical dashed line for each exploit run (markers = list of
        (id, t, name)) at its time position; hovering shows the exploit name."""
        seen = set()
        for mid, t, name in markers:
            x = -(now - t)
            if x < -_WINDOW_SECONDS:
                continue  # scrolled off the visible window
            seen.add(mid)
            s = self._marker_series.get(mid)
            if s is None:
                s = QLineSeries()
                s.setName("exploit")
                pen = QPen(QColor("#c0392b"))
                pen.setWidth(2)
                pen.setStyle(Qt.PenStyle.DashLine)
                s.setPen(pen)
                s.hovered.connect(self._on_hovered)
                self._chart.addSeries(s)
                s.attachAxis(self._axis_x)
                s.attachAxis(self._axis_y)
                # Keep exploit markers out of the (already busy) legend.
                for m in self._chart.legend().markers(s):
                    m.setVisible(False)
                self._marker_series[mid] = s
                self._marker_labels[s] = name
            s.replace([QPointF(x, 0), QPointF(x, y_top)])
        # Remove markers that have scrolled out of the window.
        for mid in list(self._marker_series):
            if mid not in seen:
                s = self._marker_series.pop(mid)
                self._marker_labels.pop(s, None)
                self._chart.removeSeries(s)

    def refresh(self, hist: dict, avg: deque, now: float, color_map: dict,
                label_map: dict | None = None, markers: list | None = None) -> None:
        if label_map:
            self._labels = label_map
        y_max = 1.0
        for service, buf in hist.items():
            color = color_map.get(service, QColor("#888888"))
            s = self._ensure_series(service, color)
            pts = []
            for t, v in buf:
                pts.append(QPointF(-(now - t), v))
                if v > y_max:
                    y_max = v
            s.replace(pts)
        self._avg.replace([QPointF(-(now - t), v) for t, v in avg])
        for _, v in avg:
            if v > y_max:
                y_max = v
        y_top = y_max * 1.1
        self._axis_y.setRange(0, y_top)
        self._draw_markers(markers or [], now, y_top)


class ResourcesPage(QWidget):
    def __init__(self, get_targets, parent=None):
        super().__init__(parent)
        self._get_targets = get_targets
        self._worker: _StatsWorker | None = None
        self._retired: list[_StatsWorker] = []   # workers finishing in the background
        # metric key -> {service -> deque[(t, value)]}, and metric -> deque[(t, avg)]
        self._hist: dict[str, dict[str, deque]] = {m[0]: defaultdict(lambda: deque(maxlen=HISTORY_POINTS)) for m in _METRICS}
        self._avg: dict[str, deque] = {m[0]: deque(maxlen=HISTORY_POINTS) for m in _METRICS}
        self._color_map: dict[str, QColor] = {}
        self._name_map: dict[str, str] = {}      # service -> full container name
        # Exploit-run markers drawn as vertical lines on every graph:
        # each entry is [id, monotonic_time, exploit_name].
        self._markers: list = []
        self._marker_counter = 0
        self._row_for_service: dict[str, int] = {}
        self._selected_service: str | None = None

        layout = QVBoxLayout(self)

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

        # htop-like table.
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

        # Three over-time charts (CPU / memory / logs), one line per container.
        self.tabs = QTabWidget()
        self._charts: dict[str, _MetricChart] = {}
        for key, title, y_title, _ in _METRICS:
            chart = _MetricChart(y_title)
            self._charts[key] = chart
            self.tabs.addTab(chart, title)
        self.tabs.currentChanged.connect(lambda _i: self._refresh_visible_chart(time.monotonic()))
        layout.addWidget(self.tabs, stretch=3)

    # ---- lifecycle: poll only while visible ----

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._start_worker()

    def hideEvent(self, event) -> None:
        super().hideEvent(event)
        self._stop_worker()

    def rebuild_targets(self) -> None:
        current = self.target_combo.currentData()
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        self._targets = list(self._get_targets())
        for t in self._targets:
            self.target_combo.addItem(t.label, t)
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
        for m in self._hist.values():
            m.clear()
        for dq in self._avg.values():
            dq.clear()
        self._color_map.clear()
        self._markers.clear()
        self._row_for_service.clear()
        self._selected_service = None
        self.table.setRowCount(0)
        # Recreate the charts to fully reset their per-service series set.
        self._recreate_charts()
        if self.isVisible():
            self._restart_worker()

    def _recreate_charts(self) -> None:
        for i, (key, title, y_title, _) in enumerate(_METRICS):
            new_chart = _MetricChart(y_title)
            old = self._charts[key]
            self.tabs.removeTab(self.tabs.indexOf(old))
            old.deleteLater()
            self._charts[key] = new_chart
            self.tabs.insertTab(i, new_chart, title)

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
        """Retire the worker WITHOUT blocking the GUI thread. It finishes its
        in-flight poll in the background then deletes itself; we hold a
        reference until then so it isn't garbage-collected mid-run."""
        w = self._worker
        self._worker = None
        if w is None:
            return
        try:
            w.sample_ready.disconnect(self._on_sample)
        except TypeError:
            pass
        w.stop()
        self._retired.append(w)
        w.finished.connect(w.deleteLater)
        w.finished.connect(lambda _w=w: self._retired.remove(_w) if _w in self._retired else None)

    def _restart_worker(self) -> None:
        self._stop_worker()
        self._start_worker()

    # ---- sample handling ----

    def _on_sample(self, resources: list) -> None:
        now = time.monotonic()
        resources = sorted(resources, key=lambda r: r.service)

        # Stable colour per service (by sorted position, stable while the set
        # of services is stable) + the full container name for hover tooltips.
        for i, r in enumerate(resources):
            self._color_map.setdefault(r.service, _series_color(i))
            self._name_map[r.service] = r.name

        # Update per-metric history + averages.
        for key, _title, _y, extract in _METRICS:
            vals = []
            for r in resources:
                v = extract(r)
                if v is not None:
                    self._hist[key][r.service].append((now, v))
                    vals.append(v)
            if vals:
                self._avg[key].append((now, sum(vals) / len(vals)))

        self._rebuild_table(resources)
        self._update_summary(resources)
        self._refresh_visible_chart(now)

    def _rebuild_table(self, resources: list) -> None:
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
        default = self.table.palette().text().color()
        for col, text in enumerate(values):
            item = self.table.item(row, col)
            if item is None or fresh:
                item = QTableWidgetItem(text)
                if col in (2, 4, 7):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self.table.setItem(row, col, item)
            else:
                item.setText(text)
            if col == 0:
                item.setForeground(self._color_map.get(r.service, default))
            elif col == 1:
                item.setForeground(QColor("#888888") if not running else default)
            elif col == 2:
                item.setForeground(cpu_color if cpu_color else default)
            elif col == 4:
                item.setForeground(mem_color if mem_color else default)

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

    # ---- charts ----

    def _refresh_visible_chart(self, now: float) -> None:
        key = _METRICS[self.tabs.currentIndex()][0]
        self._charts[key].refresh(
            self._hist[key], self._avg[key], now, self._color_map,
            self._name_map, self._markers)

    def add_exploit_marker(self, name: str) -> None:
        """Called (via MainWindow) when an exploit is run from the Exploits
        page: drop a vertical marker at the current time onto every graph,
        labelled with the exploit name. Markers persist until they scroll out
        of the ~5-minute window."""
        now = time.monotonic()
        self._marker_counter += 1
        self._markers.append([self._marker_counter, now, name])
        # Prune markers older than the visible window so the list stays bounded.
        self._markers = [m for m in self._markers if now - m[1] <= _WINDOW_SECONDS]
        if self.isVisible():
            self._refresh_visible_chart(now)

    # ---- table selection (highlights the row's own colour; charts show all) ----

    def _on_row_selected(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows:
            item = self.table.item(rows[0].row(), 0)
            if item is not None:
                self._selected_service = item.text()

    def _reselect(self) -> None:
        if self._selected_service and self._selected_service in self._row_for_service:
            self.table.selectRow(self._row_for_service[self._selected_service])
