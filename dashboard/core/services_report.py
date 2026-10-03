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

import html
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from PyQt6.QtCore import QMarginsF, QRectF, QSizeF, Qt, QThread, QUrl, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QFontMetrics, QImage, QPen, QTextDocument
from PyQt6.QtPrintSupport import QPrinter

from core import resource_stats as rs
from core.container_status import classify, start_settled
from core.docker_ctl import Target
from core.exploit_report_pdf import _report_font_family, _FONT_CSS_STACK, _esc, _resource_series_color
from core import diagrams, vector_figures
from core.vector_figures import VectorFigure
from core import report_stats as st

SAMPLE_INTERVAL_S = 2.0
# When the fast cgroup sampler is available (local host), sample resources this
# often (sub-second) for a dense usage curve, and only do the heavier
# `docker compose ps` status/event check this often (it's ~0.5s per call).
FAST_SAMPLE_INTERVAL_S = 0.25
STATUS_CHECK_INTERVAL_S = 1.5
# A safety cap, not the normal end of a start recording: that is
# container_status.start_settled(). It has to outlast the slowest legitimate
# start -- on a first boot the three honeypot MySQL pools initialise one after
# another for minutes (their healthchecks allow a 420s start_period), and
# `up -d` may build images first. The old 150s cap cut recordings off while
# the databases were still coming up.
START_MAX_SECONDS = 900.0
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
    exit_code: int | None = None      # the compose command's exit code
    hit_time_cap: bool = False        # stopped by START/STOP_MAX_SECONDS, not by settling
    # (elapsed_s, cpu_pct, ram_pct) for the whole host:
    sys_samples: list = field(default_factory=list)
    # (elapsed_s, {service: (cpu_pct, mem_bytes)}):
    container_samples: list = field(default_factory=list)
    # (elapsed_s, label):
    events: list = field(default_factory=list)
    # (caption, png_path):
    stage_shots: list = field(default_factory=list)
    # Where per-container CPU/memory came from (cgroup files or docker stats).
    resource_source: str = ""


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
            elif st == "starting" and was in ("created", "running"):
                add(f"{svc} running, health pending")
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
    # Emitted once the idle "before" shot is taken and sampling is primed; the
    # Services panel launches the compose command on it, so t=0 is that launch.
    ready_to_run = pyqtSignal()

    def __init__(self, target: Target, operation: str, parent=None):
        super().__init__(parent)
        self._target = target
        self._operation = "stop" if operation == "stop" else "start"
        self._max_seconds = STOP_MAX_SECONDS if self._operation == "stop" else START_MAX_SECONDS
        self._cancel = False
        self._shot_event = threading.Event()
        self._shot_result: dict[str, str] = {}
        # Set by the Services panel when the underlying `docker compose up/down`
        # process exits, so a stop is recorded until the command actually
        # finishes rather than guessing from `ps` going empty.
        self._op_done = threading.Event()
        self._op_exit_code: int | None = None

    def cancel(self) -> None:
        self._cancel = True

    def notify_operation_finished(self, exit_code: int) -> None:
        """Called (GUI thread) when the compose command for this export exits.
        For a start that's `up -d`, which returns once every depends_on
        condition it waited on was met; for a stop it's `down`."""
        self._op_exit_code = exit_code
        self._op_done.set()

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

    def _status_map(self, expect_some: bool = False) -> dict:
        """{service: state} from `docker compose ps`. ps() returns [] on any
        failure too, and during a `down` it can fail transiently, which used
        to log every container as stopped and then started again. So when
        containers were there last time (``expect_some``), an empty answer is
        re-checked before it is believed."""
        containers = self._target.ps()
        for _ in range(2):
            if containers or not expect_some or self._cancel:
                break
            time.sleep(0.5)
            containers = self._target.ps()
        status = {}
        for c in containers:
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
            prev_cpu: tuple[int, int] | None = None
            prev_status: dict = {}
            captured_before = captured_mid = captured_end = False
            settled_at: float | None = None
            op = self._operation

            data.stage_shots.append((
                "Before: stack idle / not yet changed",
                self._grab_health("before")))
            captured_before = True

            # Fast (sub-second) per-container sampling from cgroups on a local
            # host; falls back to ~2s docker-stats sampling for a remote target.
            # The sampler is refreshed on every status check below, so a
            # start from a stopped stack switches to fast sampling as soon as
            # the first containers are running.
            sampler = rs.FastSampler(self._target)
            if sampler.available:
                sampler.sample()  # prime CPU% delta baseline
            last_status_check = -1e9
            # Baseline status before the operation, so the first check only
            # logs real changes (a stop used to open with a "started" event
            # for every container that was already running).
            prev_status = self._status_map()

            # The recording clock starts here, when the operation is launched --
            # not at thread start, so a slow "before" screenshot or sampler
            # setup can't push every sample (and event) to a late elapsed time.
            self.ready_to_run.emit()
            start = time.time()

            def _container_snap() -> dict:
                if sampler.available:
                    return {svc: (cpu, mem) for svc, cpu, mem in sampler.sample()}
                try:
                    live = rs.collect_live(self._target)
                except Exception:  # noqa: BLE001 -- best-effort
                    return {}
                return {r.service: (r.cpu_percent, r.mem_used_bytes) for r in live}

            while not self._cancel:
                elapsed = time.time() - start
                if elapsed > self._max_seconds:
                    data.hit_time_cap = True
                    break
                self.progress.emit(
                    f"Recording {op} ({int(elapsed)}s)",
                    int(min(0.95, elapsed / self._max_seconds) * 1000), 1000)

                # --- host CPU/RAM + per-container: every (sub-second) tick ---
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
                        data.sys_samples.append((round(elapsed, 2), round(cpu_pct, 1), round(ram_pct, 1)))

                snap = _container_snap()
                if snap:
                    data.container_samples.append((round(elapsed, 2), snap))

                # --- status / events / stage transitions: throttled (ps is
                # ~0.5s, so it must not run every sub-second tick) ---
                if time.time() - last_status_check >= STATUS_CHECK_INTERVAL_S:
                    last_status_check = time.time()
                    status = self._status_map(expect_some=bool(prev_status))
                    _detect_events(prev_status, status, elapsed, data.events)
                    was_status = prev_status
                    prev_status = status
                    ps = self._target.ps()
                    sampler.refresh(ps)

                    if op == "start":
                        if not captured_mid and status:
                            data.stage_shots.append((
                                "Starting: containers coming up", self._grab_health("mid")))
                            captured_mid = True
                        # Settled = `up -d` has exited AND nothing is still
                        # created/health-starting. Checking only that every
                        # container in `ps` looked ready ended the recording
                        # while services further down the dependency chain
                        # hadn't even been started yet.
                        if settled_at is None and start_settled(
                                ps, self._op_exit_code if self._op_done.is_set() else None):
                            settled_at = time.time()
                            data.exit_code = self._op_exit_code
                            if not captured_end:
                                all_healthy = all(classify(c) in ("healthy", "running", "exited_ok")
                                                  for c in ps)
                                caption = ("All containers healthy" if all_healthy
                                           else "Start finished (some containers not healthy)")
                                data.stage_shots.append((caption, self._grab_health("end")))
                                captured_end = True
                        if settled_at is not None and time.time() - settled_at > SETTLE_TAIL_S:
                            break
                    else:  # stop
                        if not captured_mid and (len(status) < len(was_status) or not status):
                            data.stage_shots.append((
                                "Stopping: containers going down", self._grab_health("mid")))
                            captured_mid = True
                        # Keep recording until the `docker compose down` process
                        # actually exits (notify_operation_finished), not merely
                        # until `ps` looks empty -- down still tears down networks
                        # after the last container is gone.
                        if self._op_done.is_set():
                            if not captured_end:
                                data.stage_shots.append((
                                    "Stopped: down command finished", self._grab_health("end")))
                                captured_end = True
                            data.exit_code = self._op_exit_code
                            break

                # Also honour a stop's completion promptly between status checks.
                if op == "stop" and self._op_done.is_set():
                    if not captured_end:
                        data.stage_shots.append((
                            "Stopped: down command finished", self._grab_health("end")))
                        captured_end = True
                    data.exit_code = self._op_exit_code
                    break

                sample_interval = FAST_SAMPLE_INTERVAL_S if sampler.available else SAMPLE_INTERVAL_S
                deadline = time.time() + sample_interval
                while time.time() < deadline and not self._cancel:
                    time.sleep(min(0.1, max(0.0, deadline - time.time())))

            # Best-effort final "settled" shot if we never captured an end state.
            if not captured_end:
                data.stage_shots.append((
                    "Final state", self._grab_health("end")))

            data.duration_s = round(time.time() - start, 1)
            data.resource_source = rs.describe_sampling(sampler, FAST_SAMPLE_INTERVAL_S)
            # Drop stages whose grab failed (empty path) so the PDF has no blanks.
            data.stage_shots = [(cap, p) for cap, p in data.stage_shots if p]
            self.finished_ok.emit(data)
        except Exception as e:  # noqa: BLE001
            self.failed.emit(f"Services graph export failed: {e}")


# ---- rendering ----

# Events closer together than this share one numbered marker (containers
# brought up by the same compose step change state within a second or so).
_MARKER_GAP_S = 1.5


def _event_markers(events: list) -> list[tuple[int, float, float, list[str]]]:
    """Group ``events`` ((elapsed, label), ...) into numbered markers:
    ``(number, first_t, last_t, labels)``. Each marker is drawn on the graphs
    as one short numbered tag, and the event key spells out what it covers,
    so labels never sit on top of the data lines."""
    out: list[tuple[int, float, float, list[str]]] = []
    for t, label in sorted(events, key=lambda e: e[0]):
        if out and t - out[-1][2] <= _MARKER_GAP_S:
            n, t0, _t1, labels = out[-1]
            out[-1] = (n, t0, t, labels + [label])
        else:
            out.append((len(out) + 1, t, t, [label]))
    return out


# How _detect_events words each state, so a marker's events can be grouped
# by what happened ("healthy: a, b, c") instead of repeating the verb.
_EVENT_STATES = ("running, health pending", "exited (error)", "started", "healthy",
                 "unhealthy", "stopped")


def _summarize_events(labels: list[str]) -> str:
    """'a healthy', 'b healthy', 'c started' -> 'healthy: a, b; started: c'."""
    groups: dict[str, list[str]] = {}
    for label in labels:
        state = next((st for st in _EVENT_STATES if label.endswith(" " + st)), "")
        svc = label[: -len(state) - 1] if state else label
        groups.setdefault(state, []).append(svc)
    return "; ".join(f"{state}: {', '.join(svcs)}" if state else ", ".join(svcs)
                     for state, svcs in groups.items())


def _ts_chart(series: dict, colors: dict, events: list, y_label: str,
              family: str, y_max: float | None = None, annotate_peak: bool = False) -> VectorFigure:
    """A multi-series time-series chart with a dashed red vertical line per
    event marker (see _event_markers). Each marker's number sits on white in a
    band above the plot, on its own row when tags would overlap -- the same
    layout the exploit report uses -- and the event key below the host chart
    says what each number means.
    ``series`` maps name -> [(t, value), ...]; ``colors`` name -> QColor."""
    W = 900
    ml, mr, mb = 64, 20, 52
    plot_w = W - ml - mr

    all_pts = [pt for pts in series.values() for pt in pts]
    times = [t for t, _ in all_pts] + [t for t, _ in events]
    t_min = 0.0  # elapsed counts from the moment the operation was launched
    t_max = max(times, default=1.0)
    span = (t_max - t_min) or 1.0
    ymax = y_max if y_max is not None else max([v for _, v in all_pts] + [1.0])
    ymax = ymax or 1.0

    def X(t):
        return ml + ((t - t_min) / span) * plot_w

    markers = [m for m in _event_markers(events) if t_min <= m[1] <= t_max]
    tag_font = QFont(family, 8)
    fm = QFontMetrics(tag_font)
    row_h = fm.height() + 3
    rows_end: list[float] = []
    placed = []  # (x, left, width, row, number)
    for n, t0, _t1, _labels in markers:
        x = X(t0)
        w = fm.horizontalAdvance(str(n)) + 8
        left = min(max(x - w / 2, 2), W - 2 - w)
        row = next((r for r, end in enumerate(rows_end) if left > end + 2), None)
        if row is None:
            rows_end.append(left + w)
            row = len(rows_end) - 1
        else:
            rows_end[row] = left + w
        placed.append((x, left, w, row, n))
    band_top = 22
    mt = band_top + len(rows_end) * row_h + 6
    H = mt + 228 + mb
    plot_h = H - mt - mb
    img, p = vector_figures.new_figure(W, H)

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
    p.drawText(6, 14, y_label)

    # Marker lines go under the data; their numbered tags are drawn last.
    for x, _left, _w, row, _n in placed:
        pen = QPen(QColor("#c62828"), 1)
        pen.setStyle(Qt.PenStyle.DashLine)
        p.setPen(pen)
        p.drawLine(int(x), band_top + row * row_h + row_h, int(x), mt + plot_h)

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
        near = None  # nearest marker within 8s: (distance, number)
        for n, t0, t1, _labels in markers:
            d = 0.0 if t0 <= tp <= t1 else min(abs(t0 - tp), abs(t1 - tp))
            if d <= 8.0 and (near is None or d < near[0]):
                near = (d, n)
        x, y = int(X(tp)), int(Y(vp))
        p.setBrush(QColor("#111111"))
        p.setPen(QPen(QColor("#111111"), 2))
        p.drawEllipse(x - 4, y - 4, 8, 8)
        p.setBrush(Qt.BrushStyle.NoBrush)
        note = (f"peak {vp:.0f}% @ {tp:.0f}s "
                + (f"(near marker {near[1]})" if near else "(transient, no logged event)"))
        p.setFont(QFont(family, 8))
        nfm = QFontMetrics(QFont(family, 8))
        nw = nfm.horizontalAdvance(note) + 8
        box = QRectF(min(x + 8, W - mr - nw), max(mt + 2, y - nfm.height() - 6), nw, nfm.height() + 2)
        p.fillRect(box, QColor("#ffffff"))
        p.setPen(QColor("#111111"))
        p.drawText(box, int(Qt.AlignmentFlag.AlignCenter), note)

    # Marker tags last, on white, above everything else.
    p.setFont(tag_font)
    for _x, left, w, row, n in placed:
        box = QRectF(left, band_top + row * row_h, w, row_h - 1)
        p.fillRect(box, QColor("#ffffff"))
        p.setPen(QPen(QColor("#c62828"), 1))
        p.drawRect(box)
        p.setPen(QColor("#c62828"))
        p.drawText(box, int(Qt.AlignmentFlag.AlignCenter), str(n))

    p.end()
    return img


def _event_key_html(events: list) -> str:
    """Key for the numbered event markers on every graph in the report."""
    markers = _event_markers(events)
    if not markers:
        return ""
    rows = "".join(
        f'<tr><td align="center" style="color:#c62828;"><b>{n}</b></td>'
        f'<td>{t0:.0f}s' + (f'&ndash;{t1:.0f}s' if round(t1) != round(t0) else '') + '</td>'
        f'<td>{_esc(_summarize_events(labels))}</td></tr>'
        for n, t0, t1, labels in markers)
    return ('<p style="color:#222;"><b>Event key</b> (marker numbers on all graphs)</p>'
            '<table width="100%" cellspacing="0" cellpadding="3" border="1" '
            'style="border-collapse:collapse; color:#444; font-size:10px;">'
            '<tr><th>Marker</th><th>Elapsed</th><th>What happened</th></tr>' + rows + '</table>')


# Load levels whose share of the recording the host table reports.
_LEVELS_PCT = (50.0, 80.0)


def _host_stats_html(sys_samples: list) -> str:
    """Host CPU and RAM over the recorded window: mean and SD, the 95th
    percentile and peak, how far the peak sits from normal, and the chance a
    random moment of the window was at or above each load level.

    No confidence interval of the mean here: the window IS the whole run, and
    a single start/stop can't say how the next one would differ."""
    rows = []
    for idx, name in ((1, "Host CPU"), (2, "Host RAM used")):
        vals = [smp[idx] for smp in sys_samples]
        s = st.summarize(vals)
        if s is None:
            continue
        rows.append((f"{name}, mean &plusmn; SD", f"{s.mean:.1f}% &plusmn; {s.sd:.1f}",
                     f"average over {s.n} samples; the SD is the typical swing around it"))
        rows.append((f"{name}, 95th percentile / peak", f"{s.p95:.1f}% / {s.max:.1f}%",
                     "95% of the time usage was at or below the first figure"))
        if s.sd > 0:
            z = (s.max - s.mean) / s.sd
            rows.append((f"{name}, how unusual the peak is", f"{z:.1f} SD above the mean",
                         "more than ~3 SD is a rare spike rather than normal fluctuation"))
        for level in _LEVELS_PCT:
            share = st.exceedance(vals, level)
            rows.append((f"{name}, P(&ge;{level:.0f}%)", st.fmt_pct(share, 1),
                         "chance a random moment of this recording was at least this busy"))
    return st.stats_table_html(rows, "Probability metrics: host")


def _container_stats_html(container_samples: list, svcs: list) -> str:
    """One row per container: mean CPU and SD, 95th percentile and peak CPU,
    the share of the window above 50% CPU, mean memory and SD."""
    rows = []
    for svc in svcs:
        cpu_vals = [snap[svc][0] for _, snap in container_samples if svc in snap]
        cpu = st.summarize(cpu_vals)
        mem = st.summarize([snap[svc][1] / 1048576.0 for _, snap in container_samples
                            if svc in snap])
        if cpu is None or mem is None:
            continue
        rows.append(
            '<tr>'
            f'<td>{_esc(svc)}</td>'
            f'<td>{cpu.mean:.1f}% &plusmn; {cpu.sd:.1f}</td>'
            f'<td>{cpu.p95:.1f}% / {cpu.max:.1f}%</td>'
            f'<td>{st.fmt_pct(st.exceedance(cpu_vals, 50.0), 1)}</td>'
            f'<td>{mem.mean:.0f} &plusmn; {mem.sd:.0f}</td>'
            f'<td>{mem.max:.0f}</td>'
            '</tr>')
    if not rows:
        return ""
    return ('<table width="100%" cellspacing="0" cellpadding="3" border="1" '
            'style="border-collapse:collapse; font-size:9pt; margin-top:4px; color:#333;">'
            '<tr style="background-color:#eef3f8;"><th align="left" colspan="6">'
            'Probability metrics: per container</th></tr>'
            '<tr><th align="left">Container</th><th align="left">CPU mean &plusmn; SD</th>'
            '<th align="left">CPU p95 / peak</th><th align="left">P(CPU &ge; 50%)</th>'
            '<th align="left">Memory MiB, mean &plusmn; SD</th>'
            '<th align="left">Memory MiB, peak</th></tr>' + "".join(rows) + '</table>'
            '<p style="color:#666; font-size:9pt;">P(CPU &ge; 50%) is the share of the '
            'recording the container spent at half a core or more, i.e. the chance of '
            'catching it that busy at a random moment. A peak far above the p95 means a '
            'short burst (typically start-up work or a first healthcheck) rather than '
            'sustained load.</p>')


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
                 + (f' &nbsp;&middot;&nbsp; compose exit code: <b>{data.exit_code}</b>'
                    if data.exit_code is not None else '')
                 + '</td></tr></table><hr/>')
    if data.hit_time_cap:
        parts.append('<p style="color:#b35900;"><b>Recording hit its time limit</b> '
                     f'({data.duration_s:.0f}s) before the stack settled, so the charts end '
                     'while containers were still changing state.</p>')
    parts.append('<p style="color:#555;">Resource usage recorded while the stack was '
                 f'{"brought up" if data.operation == "start" else "taken down"}. Each dashed '
                 'red vertical line marks a major event (a container starting, going healthy or '
                 'unhealthy, or stopping), numbered in a band above the graph; events within '
                 f'{_MARKER_GAP_S:g}s of each other share one number, and the event key under the '
                 'host graph says what each number covers. The largest CPU peak is called out '
                 'with the marker it lines up with. <b>Figure 1</b> shows how these services fit together &ndash; '
                 'the per-container graphs below track each box in it.</p>')
    parts.append(st.GLOSSARY_HTML)
    parts.append(diagrams.figure_html(
        doc, diagrams.architecture_diagram(family), "svc-arch", 1,
        "System architecture: the services whose CPU / memory the per-container charts below "
        "track as the stack is " + ("started." if data.operation == "start" else "stopped.")))

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
        vector_figures.add_figure(doc, "svc://sys", img)
        parts.append('<img src="svc://sys" width="640"/><br/>')
        parts.append(f'<span style="color:#444; font-size:10px;">'
                     f'<span style="color:{_SYS_CPU_COLOR};">&#9632;</span> host CPU % &nbsp; '
                     f'<span style="color:{_SYS_RAM_COLOR};">&#9632;</span> host RAM % used</span>')
        parts.append(_event_key_html(data.events))
        parts.append(_host_stats_html(data.sys_samples))
    else:
        parts.append('<p style="color:#c62828;">Host CPU/RAM was not available on this target.</p>')

    # 2. per-container charts (CPU, memory)
    parts.append('<h2 style="color:#222;">2. Per-container</h2>')
    if data.resource_source:
        parts.append('<p style="color:#666666;">CPU and memory were '
                     + html.escape(data.resource_source) + '.</p>')
    if data.container_samples:
        svcs = sorted({s for _, snap in data.container_samples for s in snap})
        cmap = {s: _resource_series_color(i) for i, s in enumerate(svcs)}
        cpu_series = {s: [(t, snap[s][0]) for t, snap in data.container_samples if s in snap] for s in svcs}
        mem_series = {s: [(t, snap[s][1] / 1048576.0) for t, snap in data.container_samples if s in snap] for s in svcs}
        cpu_img = _ts_chart(cpu_series, cmap, data.events, "container CPU %", family)
        mem_img = _ts_chart(mem_series, cmap, data.events, "container memory (MiB)", family)
        vector_figures.add_figure(doc, "svc://cpu", cpu_img)
        vector_figures.add_figure(doc, "svc://mem", mem_img)
        parts.append('<img src="svc://cpu" width="640"/><br/>')
        parts.append('<img src="svc://mem" width="640"/><br/>')
        legend = " &nbsp; ".join(
            f'<span style="color:{cmap[s].name()};">&#9632;</span> {_esc(s)}' for s in svcs)
        parts.append(f'<span style="color:#444; font-size:10px;">Legend: {legend}</span>')
        parts.append(_container_stats_html(data.container_samples, svcs))
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
        markers = _event_markers(data.events)
        rows = "".join(
            f'<tr><td>{next(n for n, t0, t1, _l in markers if t0 <= t <= t1)}</td>'
            f'<td>{t:.0f}s</td><td>{_esc(lab)}</td></tr>'
            for t, lab in sorted(data.events, key=lambda e: e[0]))
        parts.append('<table cellspacing="0" cellpadding="3" border="1" '
                     'style="border-collapse:collapse; color:#444;">'
                     '<tr><th>Marker</th><th>Elapsed</th><th>Event</th></tr>' + rows + '</table>')
    else:
        parts.append('<p style="color:#666;">No container transitions were observed.</p>')

    parts.append('</div>')
    doc.setHtml("<body>" + "".join(parts) + "</body>")
    vector_figures.embed_figures(doc)

    from PyQt6.QtGui import QPageSize, QPageLayout
    printer = QPrinter(QPrinter.PrinterMode.ScreenResolution)
    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
    printer.setOutputFileName(out_path)
    printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    printer.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Unit.Millimeter)
    doc.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.DevicePixel).size()))
    doc.print(printer)
