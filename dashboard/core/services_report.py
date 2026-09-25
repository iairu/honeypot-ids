"""Start/Stop-with-graph-export for the Services page.

While the user starts or stops a stack, this samples -- in the background --
overall host CPU/RAM (from /proc, local or over SSH) plus per-container CPU and
memory (docker stats), watches `docker compose ps` for major events (containers
appearing, going healthy/unhealthy, stopping) and grabs the dashboard's Health
page at a few stages (before / coming up / settled). It then renders a single
PDF, in the same bundled Baskerville face as the exploit report, with:

  * an overall system CPU % + RAM % chart,
  * per-container CPU and memory charts,
  * a dashed vertical line on every chart for each major event,
  * a callout explaining the largest CPU peak (which event it lines up with,
    or that it was a transient with no logged cause),
  * the Health-page screenshots showing the stack change state.

The worker (a QThread) only MEASURES; the Services panel runs the actual
`docker compose up -d` / `down` alongside it. Screenshots must be taken on the
GUI thread, so -- like core.exploit_report -- the worker emits a request and
blocks on an event until the GUI thread hands back a PNG path.
"""
from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from PyQt6.QtCore import QMarginsF, QSizeF, Qt, QThread, QUrl, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QImage, QPainter, QPen, QTextDocument
from PyQt6.QtPrintSupport import QPrinter

from core import resource_stats as rs
from core.container_status import classify, is_ready
from core.docker_ctl import Target
from core.exploit_report_pdf import _report_font_family, _FONT_CSS_STACK, _esc, _resource_series_color

SAMPLE_INTERVAL_S = 2.0
START_MAX_SECONDS = 150.0
STOP_MAX_SECONDS = 90.0
# Keep sampling this long after the stack first looks settled, to catch the
# post-startup tail (background jobs, first healthchecks).
SETTLE_TAIL_S = 8.0

_SYS_CPU_COLOR = "#1565c0"
_SYS_RAM_COLOR = "#e08a00"


@dataclass
class ServicesReport:
    generated_at: str = ""
    target_label: str = ""
    operation: str = "start"          # "start" | "stop"
    duration_s: float = 0.0
    # (elapsed_s, cpu_pct, ram_pct) for the whole host:
    sys_samples: list = field(default_factory=list)
    # (elapsed_s, {service: (cpu_pct, mem_bytes)}):
    container_samples: list = field(default_factory=list)
    # (elapsed_s, label):
    events: list = field(default_factory=list)
    # (caption, png_path):
    stage_shots: list = field(default_factory=list)


# ---- host /proc sampling (works local or over SSH via Target.build_shell) ----

def _read_system(target: Target) -> tuple[int, int, int, int] | None:
    """(cpu_total_jiffies, cpu_idle_jiffies, mem_total_kb, mem_avail_kb) from the
    host's /proc, or None if unavailable."""
    argv, cwd = target.build_shell("cat /proc/stat /proc/meminfo")
    try:
        res = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if res.returncode != 0:
        return None
    cpu_total = cpu_idle = 0
    mem_total = mem_avail = 0
    for line in res.stdout.splitlines():
        if line.startswith("cpu ") and cpu_total == 0:
            parts = line.split()[1:]
            nums = [int(p) for p in parts if p.isdigit()]
            if len(nums) >= 5:
                cpu_total = sum(nums)
                cpu_idle = nums[3] + nums[4]  # idle + iowait
        elif line.startswith("MemTotal:"):
            mem_total = int(line.split()[1])
        elif line.startswith("MemAvailable:"):
            mem_avail = int(line.split()[1])
    if cpu_total == 0 or mem_total == 0:
        return None
    return cpu_total, cpu_idle, mem_total, mem_avail


def _detect_events(prev: dict, cur: dict, elapsed: float, events: list) -> None:
    """Append human-readable transition events by diffing per-service status."""
    def add(label):
        if not events or events[-1][1] != label:
            events.append((round(elapsed, 1), label))
    for svc, st in cur.items():
        was = prev.get(svc)
        if was is None:
            add(f"{svc} started")
        elif st != was:
            if st == "healthy":
                add(f"{svc} healthy")
            elif st == "unhealthy":
                add(f"{svc} unhealthy")
            elif st == "exited_bad":
                add(f"{svc} exited (error)")
    for svc in prev:
        if svc not in cur:
            add(f"{svc} stopped")


class ServicesReportWorker(QThread):
    progress = pyqtSignal(str, int, int)       # message, current, total (per-mille)
    health_shot_request = pyqtSignal(str)      # caption/key -> GUI grabs Health page
    finished_ok = pyqtSignal(object)           # ServicesReport
    failed = pyqtSignal(str)

    def __init__(self, target: Target, operation: str, parent=None):
        super().__init__(parent)
        self._target = target
        self._operation = "stop" if operation == "stop" else "start"
        self._max_seconds = STOP_MAX_SECONDS if self._operation == "stop" else START_MAX_SECONDS
        self._cancel = False
        self._shot_event = threading.Event()
        self._shot_result: dict[str, str] = {}

    def cancel(self) -> None:
        self._cancel = True

    def provide_health_shot(self, key: str, path: str) -> None:
        """Called on the GUI thread with the grabbed Health-page PNG path."""
        self._shot_result[key] = path
        self._shot_event.set()

    def _grab_health(self, key: str) -> str:
        if self._cancel:
            return ""
        self._shot_event.clear()
        self._shot_result.pop(key, None)
        self.health_shot_request.emit(key)
        self._shot_event.wait(timeout=15)
        return self._shot_result.get(key, "")

    def _status_map(self) -> dict:
        status = {}
        for c in self._target.ps():
            svc = c.get("Service") or c.get("Name") or ""
            if svc:
                status[svc] = classify(c)
        return status

    def run(self) -> None:
        try:
            data = ServicesReport(
                generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                target_label=self._target.label,
                operation=self._operation,
            )
            start = time.time()
            prev_cpu: tuple[int, int] | None = None
            prev_status: dict = {}
            captured_before = captured_mid = captured_end = False
            settled_at: float | None = None
            op = self._operation

            data.stage_shots.append((
                "Before: stack idle / not yet changed",
                self._grab_health("before")))
            captured_before = True

            while not self._cancel:
                elapsed = time.time() - start
                if elapsed > self._max_seconds:
                    break
                self.progress.emit(
                    f"Recording {op} ({int(elapsed)}s)",
                    int(min(0.95, elapsed / self._max_seconds) * 1000), 1000)

                sysread = _read_system(self._target)
                if sysread:
                    ct, ci, mt, ma = sysread
                    cpu_pct = None
                    if prev_cpu is not None:
                        dt = ct - prev_cpu[0]
                        di = ci - prev_cpu[1]
                        if dt > 0:
                            cpu_pct = max(0.0, min(100.0, 100.0 * (1.0 - di / dt)))
                    prev_cpu = (ct, ci)
                    ram_pct = 100.0 * (1.0 - ma / mt) if mt else 0.0
                    if cpu_pct is not None:
                        data.sys_samples.append((round(elapsed, 1), round(cpu_pct, 1), round(ram_pct, 1)))

                try:
                    live = rs.collect_live(self._target)
                except Exception:  # noqa: BLE001 -- best-effort
                    live = []
                if live:
                    snap = {r.service: (r.cpu_percent, r.mem_used_bytes) for r in live}
                    data.container_samples.append((round(elapsed, 1), snap))

                status = self._status_map()
                _detect_events(prev_status, status, elapsed, data.events)
                prev_status = status

                ps = self._target.ps()
                all_ready = bool(ps) and all(is_ready(c) for c in ps)

                if op == "start":
                    if not captured_mid and status:
                        data.stage_shots.append((
                            "Starting: containers coming up", self._grab_health("mid")))
                        captured_mid = True
                    if all_ready and settled_at is None:
                        settled_at = time.time()
                        if not captured_end:
                            data.stage_shots.append((
                                "All containers healthy", self._grab_health("end")))
                            captured_end = True
                    if settled_at is not None and time.time() - settled_at > SETTLE_TAIL_S:
                        break
                else:  # stop
                    if not captured_mid and (len(status) < len(prev_status) or not status):
                        data.stage_shots.append((
                            "Stopping: containers going down", self._grab_health("mid")))
                        captured_mid = True
                    if not status:
                        if not captured_end:
                            data.stage_shots.append((
                                "Stopped: no containers", self._grab_health("end")))
                            captured_end = True
                        break

                deadline = time.time() + SAMPLE_INTERVAL_S
                while time.time() < deadline and not self._cancel:
                    time.sleep(min(0.4, max(0.0, deadline - time.time())))

            # Best-effort final "settled" shot if we never captured an end state.
            if not captured_end:
                data.stage_shots.append((
                    "Final state", self._grab_health("end")))

            data.duration_s = round(time.time() - start, 1)
            # Drop stages whose grab failed (empty path) so the PDF has no blanks.
            data.stage_shots = [(cap, p) for cap, p in data.stage_shots if p]
            self.finished_ok.emit(data)
        except Exception as e:  # noqa: BLE001
            self.failed.emit(f"Services graph export failed: {e}")


# ---- rendering ----

def _ts_chart(series: dict, colors: dict, events: list, y_label: str,
              family: str, y_max: float | None = None, annotate_peak: bool = False) -> QImage:
    """A multi-series time-series chart with a dashed vertical line per event.
    ``series`` maps name -> [(t, value), ...]; ``colors`` name -> QColor."""
    W, H = 900, 320
    ml, mr, mt, mb = 64, 20, 40, 52
    img = QImage(W, H, QImage.Format.Format_ARGB32)
    img.fill(QColor("#ffffff"))
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    plot_w, plot_h = W - ml - mr, H - mt - mb

    all_pts = [pt for pts in series.values() for pt in pts]
    times = [t for t, _ in all_pts] + [t for t, _ in events]
    t_min = min(times, default=0.0)
    t_max = max(times, default=1.0)
    span = (t_max - t_min) or 1.0
    ymax = y_max if y_max is not None else max([v for _, v in all_pts] + [1.0])
    ymax = ymax or 1.0

    def X(t):
        return ml + ((t - t_min) / span) * plot_w

    def Y(v):
        return mt + (1 - min(v, ymax) / ymax) * plot_h

    p.setFont(QFont(family, 9))
    p.setPen(QPen(QColor("#333333"), 2))
    p.drawLine(ml, mt, ml, mt + plot_h)
    p.drawLine(ml, mt + plot_h, ml + plot_w, mt + plot_h)
    for k in range(5):
        v = ymax * k / 4
        y = int(Y(v))
        p.setPen(QPen(QColor("#e6e6e6"), 1))
        p.drawLine(ml, y, ml + plot_w, y)
        p.setPen(QColor("#333333"))
        p.drawText(6, y + 4, f"{v:.0f}")
    for k in range(6):
        t = t_min + span * k / 5
        p.setPen(QColor("#333333"))
        p.drawText(int(X(t)) - 10, mt + plot_h + 18, f"{t:.0f}s")
    p.setPen(QColor("#111111"))
    p.drawText(ml, mt - 12, y_label)

    # Event vertical lines (dashed, red), staggered labels to reduce overlap.
    for i, (t, label) in enumerate(events):
        if not (t_min <= t <= t_max):
            continue
        x = int(X(t))
        pen = QPen(QColor("#c62828"), 1)
        pen.setStyle(Qt.PenStyle.DashLine)
        p.setPen(pen)
        p.drawLine(x, mt, x, mt + plot_h)
        p.setPen(QColor("#c62828"))
        p.setFont(QFont(family, 7))
        p.drawText(x + 2, mt + 10 + (i % 4) * 10, label[:22])
        p.setFont(QFont(family, 9))

    for name, pts in series.items():
        if not pts:
            continue
        p.setPen(QPen(colors.get(name, QColor("#333333")), 3))
        prev = None
        for t, v in pts:
            cur = (X(t), Y(v))
            if prev is not None:
                p.drawLine(int(prev[0]), int(prev[1]), int(cur[0]), int(cur[1]))
            prev = cur

    # Explain the largest CPU peak: mark the global max point and note the
    # nearest event (within 8s), else flag it as an unexplained transient.
    if annotate_peak and all_pts:
        pt_max = max(all_pts, key=lambda tv: tv[1])
        tp, vp = pt_max
        near = None
        for te, lab in events:
            if abs(te - tp) <= 8.0 and (near is None or abs(te - tp) < abs(near[0] - tp)):
                near = (te, lab)
        x, y = int(X(tp)), int(Y(vp))
        p.setBrush(QColor("#111111"))
        p.setPen(QPen(QColor("#111111"), 2))
        p.drawEllipse(x - 4, y - 4, 8, 8)
        note = (f"peak {vp:.0f}% @ {tp:.0f}s "
                + (f"(around: {near[1]})" if near else "(transient, no logged event)"))
        p.setFont(QFont(family, 8))
        tx = min(x + 6, W - 260)
        p.drawText(tx, max(mt + 12, y - 8), note)

    p.end()
    return img


def render_services_pdf(data: ServicesReport, out_path: str) -> None:
    family = _report_font_family()
    doc = QTextDocument()
    doc.setDefaultFont(QFont(family, 11))

    op_word = "start-up" if data.operation == "start" else "shutdown"
    parts: list[str] = [f'<div style="font-family: {_FONT_CSS_STACK};">']
    parts.append(f'<h1 style="color:#222;">Service {op_word} report</h1>')
    parts.append('<table width="100%" style="color:#555;"><tr><td>'
                 f'Generated: {_esc(data.generated_at)}<br/>'
                 f'Target: {_esc(data.target_label)}<br/>'
                 f'Operation: <b>{_esc(data.operation)}</b> &nbsp;&middot;&nbsp; '
                 f'Recorded window: {data.duration_s:.0f}s'
                 '</td></tr></table><hr/>')
    parts.append('<p style="color:#555;">Resource usage recorded while the stack was '
                 f'{"brought up" if data.operation == "start" else "taken down"}. Each dashed '
                 'red vertical line marks a major event (a container starting, going healthy or '
                 'unhealthy, or stopping); the largest CPU peak is called out with the event it '
                 'lines up with.</p>')

    # 1. overall system chart
    parts.append('<h2 style="color:#222;">1. Overall system (host)</h2>')
    if data.sys_samples:
        sys_series = {
            "CPU %": [(t, cpu) for t, cpu, _ in data.sys_samples],
            "RAM %": [(t, ram) for t, _, ram in data.sys_samples],
        }
        colors = {"CPU %": QColor(_SYS_CPU_COLOR), "RAM %": QColor(_SYS_RAM_COLOR)}
        img = _ts_chart(sys_series, colors, data.events, "host CPU % / RAM %",
                        family, y_max=100.0, annotate_peak=True)
        doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl("svc://sys"), img)
        parts.append('<img src="svc://sys" width="640"/><br/>')
        parts.append(f'<span style="color:#444; font-size:10px;">'
                     f'<span style="color:{_SYS_CPU_COLOR};">&#9632;</span> host CPU % &nbsp; '
                     f'<span style="color:{_SYS_RAM_COLOR};">&#9632;</span> host RAM % used</span>')
    else:
        parts.append('<p style="color:#c62828;">Host CPU/RAM was not available on this target.</p>')

    # 2. per-container charts (CPU, memory)
    parts.append('<h2 style="color:#222;">2. Per-container</h2>')
    if data.container_samples:
        svcs = sorted({s for _, snap in data.container_samples for s in snap})
        cmap = {s: _resource_series_color(i) for i, s in enumerate(svcs)}
        cpu_series = {s: [(t, snap[s][0]) for t, snap in data.container_samples if s in snap] for s in svcs}
        mem_series = {s: [(t, snap[s][1] / 1048576.0) for t, snap in data.container_samples if s in snap] for s in svcs}
        cpu_img = _ts_chart(cpu_series, cmap, data.events, "container CPU %", family)
        mem_img = _ts_chart(mem_series, cmap, data.events, "container memory (MiB)", family)
        doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl("svc://cpu"), cpu_img)
        doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl("svc://mem"), mem_img)
        parts.append('<img src="svc://cpu" width="640"/><br/>')
        parts.append('<img src="svc://mem" width="640"/><br/>')
        legend = " &nbsp; ".join(
            f'<span style="color:{cmap[s].name()};">&#9632;</span> {_esc(s)}' for s in svcs)
        parts.append(f'<span style="color:#444; font-size:10px;">Legend: {legend}</span>')
    else:
        parts.append('<p style="color:#666;">No per-container samples were captured.</p>')

    # 3. health page screenshots
    parts.append('<h2 style="color:#222;">3. Health page as the stack changes state</h2>')
    if data.stage_shots:
        for i, (caption, path) in enumerate(data.stage_shots):
            img = QImage(path)
            if img.isNull():
                continue
            doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(f"svc://shot{i}"), img)
            parts.append(f'<p style="color:#555;"><b>{_esc(caption)}</b></p>')
            parts.append(f'<img src="svc://shot{i}" width="620"/><br/>')
    else:
        parts.append('<p style="color:#666;">No Health-page screenshots were captured.</p>')

    # 4. event log
    parts.append('<h2 style="color:#222;">4. Event log</h2>')
    if data.events:
        rows = "".join(f'<tr><td>{t:.0f}s</td><td>{_esc(lab)}</td></tr>' for t, lab in data.events)
        parts.append('<table cellspacing="0" cellpadding="3" border="1" '
                     'style="border-collapse:collapse; color:#444;">'
                     '<tr><th>Elapsed</th><th>Event</th></tr>' + rows + '</table>')
    else:
        parts.append('<p style="color:#666;">No container transitions were observed.</p>')

    parts.append('</div>')
    doc.setHtml("<body>" + "".join(parts) + "</body>")

    from PyQt6.QtGui import QPageSize, QPageLayout
    printer = QPrinter(QPrinter.PrinterMode.ScreenResolution)
    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
    printer.setOutputFileName(out_path)
    printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    printer.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Unit.Millimeter)
    doc.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.DevicePixel).size()))
    doc.print(printer)
