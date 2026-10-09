"""Segmentation Validation page: 3 to 10 embedded browsers, each its own attacker session,
to see how the honeypot pool receives several attackers at once.

Every frame is a BrowserWidget, i.e. its own off-the-record profile and so its
own cookie jar -- the proxy hands each one a separate signed session cookie.
Cookies alone are not enough, though: a request that arrives WITHOUT a cookie
is matched to an existing session by a passive fingerprint (TLS hello,
User-Agent, Accept-Language, client IP; see session_identity_rules.lua), and
frames of one app on one machine would otherwise share all of it, so every
frame after the first would be folded into the first frame's session. Each
frame therefore gets its own User-Agent suffix and Accept-Language, which is
what makes the proxy see different clients.

"Attack" sends the same exploit request from the frame; once the score tips,
the session is bound to a honeypot pool. The pools scale with the number of
attacker sessions (pool_manager builds one per session until its resource
limit, then the rest share round-robin), so a window may borrow a pool for a
while and then move to its own. The pool summary (from the Redis pool
registry) shows how many pools are ready, how many sessions each owns and how
many still wait for theirs.
"""
from __future__ import annotations

import random
import time
from datetime import datetime

from PyQt6.QtCore import QEventLoop, Qt, QThread, QTimer, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QLabel, QMessageBox,
    QProgressBar, QPushButton, QSpinBox, QSplitter, QVBoxLayout, QWidget,
)

from core import redis_inspect
from core.docker_ctl import target_for
from core.exploits import EXPLOIT_PRESETS
from core import pool_evidence
from core.pool_test_report import (CART_PLAN, FALLBACK_EXPLOITS, MAX_ATTEMPTS, MAX_WINDOWS,
                                    MIN_WINDOWS, CartState, ClearEvent, Decision, ExploitRun, FrameResult,
                                    LoadTiming, PoolTestData, Sample, StepResult, UsageSample,
                                    browse_action, browse_page, classify, clear_schedule, parse_cart, parse_decision, parse_product_ids,
                                    window_plan)
from core.resource_stats import collect_pool_usage
from core.state import AppState
from ui.browser_widget import BrowserWidget
from ui.flow_layout import FlowLayout, labeled

# Name of the proxy's session cookie (init.lua: session.cookie_name).
SESSION_COOKIE = "SERVERID"

# (label, Accept-Language) per frame -- what makes the fingerprints differ.
FRAMES = [
    ("Attacker A", "en-US,en;q=0.9"),
    ("Attacker B", "de-DE,de;q=0.9"),
    ("Attacker C", "fr-FR,fr;q=0.9"),
    ("Attacker D", "es-ES,es;q=0.9"),
    ("Attacker E", "it-IT,it;q=0.9"),
    ("Attacker F", "nl-NL,nl;q=0.9"),
    ("Attacker G", "pl-PL,pl;q=0.9"),
    ("Attacker H", "sv-SE,sv;q=0.9"),
    ("Attacker I", "cs-CZ,cs;q=0.9"),
    ("Attacker J", "sk-SK,sk;q=0.9"),
]
assert len(FRAMES) == MAX_WINDOWS

# Windows per row before the frames wrap onto a second row.
ROW_MAX = 5

# How long the report waits for pool_manager to finish the forced scale-down.
SCALEDOWN_TIMEOUT_S = 300

# How long the report waits for pool_manager to build a pool for every window
# that is still borrowing one (a WordPress pool takes a few minutes).
SCALE_TIMEOUT_S = 900

# While the report waits for pools, every window opens its next page this often.
BROWSE_EVERY_S = 10.0


# Clears the page origin's localStorage and sessionStorage, the way "clear site
# data" does; returns how many entries were removed.
_CLEAR_STORAGE_JS = ("(function(){var n=0;try{n+=localStorage.length;localStorage.clear();}catch(e){}"
                     "try{n+=sessionStorage.length;sessionStorage.clear();}catch(e){}return String(n);})()")


# Reads the shop's own cart (WooCommerce Store API) from inside a window, so the
# request carries that window's cookies and is routed exactly like its own traffic.
_CART_JS = ("(function(){try{var x=new XMLHttpRequest();x.open('GET','/wp-json/wc/store/v1/cart',false);"
            "x.send();return x.responseText;}catch(e){return '';}})()")


def product_ids_js(slugs: list[str]) -> str:
    """JS that reads the product IDs for `slugs` from the shop's Store API in one
    request, run inside a window: the lookup is then an ordinary browser request
    of that window's own (production) session. Fetched from Python instead, it
    was a scripted client to the proxy, got diverted to a honeypot and took a
    free pool away from the windows (one of them then had to borrow a pool)."""
    url = "/wp-json/wc/store/v1/products?per_page=100&slug=" + ",".join(slugs)
    return ("(function(){try{var x=new XMLHttpRequest();x.open('GET','" + url + "',false);"
            "x.send();return x.responseText;}catch(e){return '';}})()")


class _Cancelled(Exception):
    """Raised inside the scenario when the user presses Cancel."""


class _Job(QThread):
    """Runs one blocking callable (docker exec / redis-cli) off the GUI thread."""

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn
        self.result = None
        self.error: Exception | None = None

    def run(self) -> None:
        try:
            self.result = self._fn()
        except Exception as e:  # noqa: BLE001 -- handed back to the GUI thread
            self.error = e


class _UsageSampler(QThread):
    """Samples the honeypot pool containers' memory/CPU every `interval`
    seconds for the whole report run, so the PDF can show resource use going
    up while pools are built and down again at the scale-down."""

    def __init__(self, target, t0: float, parent=None):
        super().__init__(parent)
        self._target, self._t0 = target, t0
        self.interval = 10.0
        self.samples: list[UsageSample] = []
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        while not self._stop:
            started = time.time()
            try:
                u = collect_pool_usage(self._target)
                self.samples.append(UsageSample(started - self._t0, u.containers, u.pools,
                                                u.mem_bytes / 2 ** 20, u.cpu_percent))
            except Exception:  # noqa: BLE001 -- a gap in the curve, not a failed run
                pass
            while not self._stop and time.time() - started < self.interval:
                self.msleep(200)


def frame_identity(base_user_agent: str, index: int) -> tuple[str, str]:
    """User-Agent and Accept-Language that make frame `index` a distinct client."""
    label, language = FRAMES[index]
    return f"{base_user_agent} PoolTest/{label[-1]}", language


def _default_eshop_url(state: AppState) -> str:
    host = state.remote_edge.host if state.remote_edge.is_configured() else "localhost"
    return f"https://{host}/"


class PoolTestPage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self._presets = [p for p in EXPLOIT_PRESETS if p.method.upper() == "GET"]

        layout = QVBoxLayout(self)

        intro = QLabel(
            "3 to 10 browsers, each a separate session (own cookies, own User-Agent and "
            "language, so the proxy cannot merge them). Open the shop in each, then attack "
            "from several at once and check that every attacker lands in a honeypot pool "
            "of their own: the pools scale with the attacker sessions until the resource "
            "limit, after which the remaining sessions share the pools round-robin.")
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #aaaaaa;")
        layout.addWidget(intro)

        # Wraps onto more rows in a narrow window instead of forcing it wider.
        bar = FlowLayout()
        self.count_spin = QSpinBox()
        self.count_spin.setRange(MIN_WINDOWS, MAX_WINDOWS)
        self.count_spin.setValue(MIN_WINDOWS)
        self.count_spin.setToolTip(
            "How many browser windows (separate attacker sessions) to run side by side.")
        self.count_spin.valueChanged.connect(self.set_window_count)
        bar.addWidget(labeled("Windows:", self.count_spin))
        self.delayed_spin = QSpinBox()
        self.delayed_spin.setRange(0, MIN_WINDOWS)
        self.delayed_spin.setValue(0)
        self.delayed_spin.setToolTip(
            "How many of the windows (the last ones) attack only after the honeypot pool "
            "has been scaled up for them: the report first asks pool_manager for that many "
            "free pools and waits until they are ready, so these windows get a pool of their "
            "own at once instead of borrowing one round-robin. The other windows attack "
            "straight away and show the round-robin borrowing while pools are still being "
            "built.")
        bar.addWidget(labeled("of which wait for pools:", self.delayed_spin))
        self.preset_combo = QComboBox()
        for p in self._presets:
            self.preset_combo.addItem(f"{p.cve} — {p.name}")
        self.preset_combo.setMinimumWidth(320)
        bar.addWidget(labeled("Exploit:", self.preset_combo))
        self.open_all_btn = QPushButton("Open shop in all")
        self.open_all_btn.clicked.connect(self.open_all)
        bar.addWidget(self.open_all_btn)
        self.attack_all_btn = QPushButton("Attack from all")
        self.attack_all_btn.clicked.connect(self.attack_all)
        bar.addWidget(self.attack_all_btn)
        self.reset_btn = QPushButton("New sessions")
        self.reset_btn.setToolTip("Clear every frame's cookies, so each starts a fresh session.")
        self.reset_btn.clicked.connect(self.reset_sessions)
        bar.addWidget(self.reset_btn)
        self.clear_check = QCheckBox("Clear browser data in random windows")
        self.clear_check.setChecked(True)
        self.clear_check.setToolTip(
            "During the report run, a few random windows clear their own cookies and/or "
            "localStorage between steps, the way a regular visitor clears their browsing "
            "data. The PDF shows each time it happened and what the stack did with the "
            "window afterwards (its old session back or a fresh one, and which pool).")
        bar.addWidget(self.clear_check)
        self.export_btn = QPushButton("Export report (PDF)")
        self.export_btn.setToolTip(
            "Which honeypot pool each window's session landed in, and whether that matches "
            "one attacker per pool (shared only when pools run out).")
        self.export_btn.clicked.connect(self.export_report)
        bar.addWidget(self.export_btn)
        layout.addLayout(bar)

        # In-page progress row (not a floating dialog, so it can never land in
        # the frames' screenshots) -- same pattern as the Attack Simulation page.
        self.progress_row = QWidget()
        prog = QHBoxLayout(self.progress_row)
        prog.setContentsMargins(0, 0, 0, 0)
        self.progress_label = QLabel("Preparing report...")
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(320)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self._cancel_report)
        prog.addWidget(self.progress_label, stretch=1)
        prog.addWidget(self.progress_bar)
        prog.addWidget(self.cancel_btn)
        self.progress_row.setVisible(False)
        layout.addWidget(self.progress_row)
        self._exporting = False
        self._cancelled = False
        self._job: _Job | None = None
        # Report run timeline: seconds since its start (0 = no run going).
        self._t0 = 0.0
        self._samples: list[Sample] = []
        self._loads: list[LoadTiming] = []
        self._pending_loads: list[LoadTiming] = []
        self._marks: list[tuple[float, str]] = []
        self._reserve: dict = {}
        self._baseline: dict = {}   # pool_evidence baseline of the running report

        self.pool_label = QLabel("")
        self.pool_label.setWordWrap(True)
        self.refresh_btn = QPushButton("Refresh pool state")
        self.refresh_btn.clicked.connect(self.refresh_pool_state)
        row = QHBoxLayout()
        row.addWidget(self.pool_label, stretch=1)
        row.addWidget(self.refresh_btn)
        layout.addLayout(row)

        # Frames are created on demand and only hidden (cookies cleared) when the
        # window count goes down, so a QWebEngine profile is never torn down
        # while its page is alive. Up to ROW_MAX per row, then a second row.
        self._rows = QSplitter(Qt.Orientation.Vertical)
        self._row_splitters = [QSplitter(Qt.Orientation.Horizontal) for _ in range(2)]
        for row in self._row_splitters:
            self._rows.addWidget(row)
        layout.addWidget(self._rows, stretch=1)
        self._count = 0
        self._boxes: list[QGroupBox] = []
        self._all_browsers: list[BrowserWidget] = []
        self._all_decisions: list[QLabel] = []
        self._all_carts: list[QLabel] = []
        # Per frame: the session id from the SERVERID cookie the proxy set it
        # ("<id>.<mac>"), kept up to date from the profile's cookie store.
        self._session_ids = [""] * MAX_WINDOWS
        self._cookie_names: list[set[str]] = [set() for _ in range(MAX_WINDOWS)]
        self._visits = [0] * MAX_WINDOWS          # pages each window has browsed this run
        self._seen: list[list[str]] = [[] for _ in range(MAX_WINDOWS)]   # ... this step
        self.set_window_count(MIN_WINDOWS)

        # Keeps the labels under the frames current while browsing by hand.
        self._poll = QTimer(self)
        self._poll.setInterval(3000)
        self._poll.timeout.connect(self.refresh_decisions)

    # ---- frames ----

    @property
    def browsers(self) -> list[BrowserWidget]:
        return self._all_browsers[:self._count]

    @property
    def decision_labels(self) -> list[QLabel]:
        return self._all_decisions[:self._count]

    @property
    def cart_labels(self) -> list[QLabel]:
        return self._all_carts[:self._count]

    def _add_frame(self) -> None:
        i = len(self._boxes)
        label = FRAMES[i][0]
        browser = BrowserWidget()
        ua, lang = frame_identity(browser.profile.httpUserAgent(), i)
        browser.profile.setHttpUserAgent(ua)
        browser.profile.setHttpAcceptLanguage(lang)
        store = browser.profile.cookieStore()
        store.cookieAdded.connect(lambda c, n=i: self._on_cookie(n, c))
        store.cookieRemoved.connect(lambda c, n=i: self._on_cookie_removed(n, c))
        store.loadAllCookies()

        box = QGroupBox(label)
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(4, 4, 4, 4)
        attack_btn = QPushButton(f"Attack from {label[-1]}")
        attack_btn.clicked.connect(lambda _=False, n=i: self.attack(n))
        box_layout.addWidget(attack_btn)
        box_layout.addWidget(browser, stretch=1)
        decision = QLabel("Routing: no session yet")
        decision.setWordWrap(True)
        decision.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box_layout.addWidget(decision)
        cart = QLabel("Cart: —")
        cart.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cart.setStyleSheet("QLabel { color: #cfcfcf; padding: 2px 8px; border: 1px solid #555; border-radius: 4px; }")
        box_layout.addWidget(cart)
        self._boxes.append(box)
        self._all_browsers.append(browser)
        self._all_decisions.append(decision)
        self._all_carts.append(cart)
        self._row_splitters[0].addWidget(box)

    def set_window_count(self, n: int) -> None:
        """Show `n` frames. Frames beyond it are hidden and their session
        dropped (cookies cleared, page blanked), so they stop counting."""
        if self._exporting:
            return
        n = max(MIN_WINDOWS, min(MAX_WINDOWS, n))
        while len(self._boxes) < n:
            self._add_frame()
        for i in range(n, self._count):
            self._all_browsers[i].clear_cookies()
            self._all_browsers[i].navigate("about:blank")
            self._session_ids[i] = ""
        self._count = n
        per_row = n if n <= ROW_MAX else (n + 1) // 2
        for i, box in enumerate(self._boxes):
            if i >= n:
                box.hide()
                continue
            self._row_splitters[0 if i < per_row else 1].addWidget(box)
            box.show()
            self._style_decision(i, Decision())
        self._row_splitters[1].setVisible(n > per_row)
        for row in self._row_splitters:
            row.setSizes([1000 if not w.isHidden() else 0
                          for w in (row.widget(k) for k in range(row.count()))])
        self._rows.setSizes([1000, 1000 if n > per_row else 0])
        if self.count_spin.value() != n:
            self.count_spin.setValue(n)
        self.delayed_spin.setMaximum(n)

    def _delayed(self) -> int:
        return min(self.delayed_spin.value(), self._count)

    def _base_url(self) -> str:
        return _default_eshop_url(self.state).rstrip("/")

    def _preset(self):
        i = self.preset_combo.currentIndex()
        return self._presets[i] if 0 <= i < len(self._presets) else None

    def open_all(self) -> None:
        for browser in self.browsers:
            browser.navigate(self._base_url() + "/")

    def attack(self, index: int) -> None:
        preset = self._preset()
        if preset is not None:
            self.browsers[index].navigate(self._base_url() + preset.path)

    def attack_all(self) -> None:
        for i in range(len(self.browsers)):
            self.attack(i)

    def _on_cookie(self, index: int, cookie) -> None:
        name = bytes(cookie.name()).decode(errors="replace")
        self._cookie_names[index].add(name)
        if name == SESSION_COOKIE:
            value = bytes(cookie.value()).decode(errors="replace")
            self._session_ids[index] = value.split(".", 1)[0]

    def _on_cookie_removed(self, index: int, cookie) -> None:
        name = bytes(cookie.name()).decode(errors="replace")
        self._cookie_names[index].discard(name)
        if name == SESSION_COOKIE:
            self._session_ids[index] = ""

    # ---- routing decision under each frame ----

    def _style_decision(self, index: int, d: Decision) -> None:
        color = {"HONEYPOT": "#e08a00", "PRODUCTION": "#5cb85c"}.get(d.route, "#777777")
        label = self.decision_labels[index]
        label.setText(d.text())
        label.setStyleSheet(
            f"QLabel {{ background-color: {color}; color: #1e1e1e; padding: 4px 10px; "
            "border-radius: 4px; font-weight: bold; }")

    def _style_cart(self, index: int, cart: CartState | None) -> None:
        label = self.cart_labels[index]
        if cart is None:
            label.setText("Cart: —")
            label.setStyleSheet("QLabel { color: #cfcfcf; padding: 2px 8px; border: 1px solid #555; border-radius: 4px; }")
            return
        label.setText(cart.text())
        color = "#5cb85c" if cart.items else "#cfcfcf"
        label.setStyleSheet(f"QLabel {{ color: {color}; padding: 2px 8px; border: 1px solid {color}; border-radius: 4px; }}")

    def _read_cart(self, index: int) -> CartState | None:
        """The window's cart as the shop (production or its honeypot pool) reports it."""
        browser = self.browsers[index]
        if not browser.view.url().toString().startswith("http"):
            return None
        return parse_cart(self._run_js(index, _CART_JS))

    def _run_js(self, index: int, script: str, timeout_ms: int = 6000) -> str:
        """Run `script` in window `index` and return its result ("" on timeout)."""
        loop = QEventLoop()
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        got: list = [None]

        def done(result) -> None:
            got[0] = result
            loop.quit()
        self.browsers[index].page.runJavaScript(script, done)
        timer.start(timeout_ms)
        loop.exec()
        timer.stop()
        return got[0] or ""

    def _read_carts(self) -> list[CartState | None]:
        carts = [self._read_cart(i) for i in range(len(self.browsers))]
        for i, c in enumerate(carts):
            self._style_cart(i, c)
        return carts

    def _refresh_cart_labels(self) -> None:
        """Non-blocking cart refresh for the live labels."""
        for i, browser in enumerate(self.browsers):
            if browser.view.url().toString().startswith("http"):
                browser.page.runJavaScript(
                    _CART_JS, lambda r, n=i: self._style_cart(n, parse_cart(r or "")))

    def _remote(self):
        return target_for("edge", self.state).remote

    def _fetch_decisions(self, sids: list[str]) -> list[Decision]:
        remote = self._remote()

        def read() -> list[Decision]:
            out = []
            for sid in sids:
                if not sid:
                    out.append(Decision())
                    continue
                raw, pool, waiting = redis_inspect.session_decision_raw(remote, sid)
                out.append(parse_decision(sid, raw, pool, waiting))
            return out
        return read()

    def refresh_decisions(self) -> None:
        """Async refresh of the labels (skipped while a read or an export runs)."""
        if self._exporting or self._job is not None or not self.isVisible():
            return
        sids = self._session_ids[:self._count]
        job = _Job(lambda: self._fetch_decisions(sids), self)
        self._job = job

        def done() -> None:
            self._job = None
            if job.error is None and not self._exporting:
                for i, d in enumerate(job.result or []):
                    self._style_decision(i, d)
                self._refresh_cart_labels()
            job.deleteLater()
        job.finished.connect(done)
        job.start()

    def _blocking(self, fn):
        """Run `fn` on a worker thread while the GUI keeps painting (the frames
        keep loading); returns its result or raises its error."""
        job = _Job(fn, self)
        loop = QEventLoop()
        job.finished.connect(loop.quit)
        job.start()
        loop.exec()
        job.wait()
        job.deleteLater()
        if job.error is not None:
            raise job.error
        return job.result

    @staticmethod
    def _spin(ms: int) -> None:
        loop = QEventLoop()
        QTimer.singleShot(ms, loop.quit)
        loop.exec()

    # ---- report export (progress bar, all frames move every step) ----

    def _cancel_report(self) -> None:
        self._cancelled = True
        self.cancel_btn.setEnabled(False)
        self.progress_label.setText("Cancelling...")

    def _progress(self, message: str, current: int, total: int) -> None:
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.progress_label.setText(message)

    def _load_all(self, urls: list[str], step: str = "") -> None:
        """Navigate each frame to its URL and wait for all loads (hard timeout,
        so one stuck page cannot hang the export). Each completed load's time
        is recorded for the latency figures, under `step`; its routing state is
        filled in by the next _observe()."""
        # A frame already on about:blank never fires loadFinished for about:blank.
        pending = {i for i, u in enumerate(urls)
                   if not (u == "about:blank" and self.browsers[i].view.url().toString()
                           in ("", "about:blank"))}
        loop = QEventLoop()
        if not pending:
            for browser, url in zip(self.browsers, urls):
                browser.navigate(url)
            return
        started = time.monotonic()
        t = self._now()
        conns = []
        for i, (browser, url) in enumerate(zip(self.browsers, urls)):
            def finished(ok, n=i, u=url):
                if ok and u.startswith("http") and n in pending and self._t0:
                    self._pending_loads.append(LoadTiming(
                        t, n, step, (time.monotonic() - started) * 1000.0))
                pending.discard(n)
                if not pending:
                    loop.quit()
            conns.append((browser, browser.view.loadFinished.connect(finished)))
            browser.navigate(url)
        timer = QTimer(self)   # stoppable: a stale single-shot would cut a later wait short
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        timer.start(9000)
        loop.exec()
        timer.stop()
        for browser, conn in conns:
            try:
                browser.view.loadFinished.disconnect(conn)
            except TypeError:
                pass

    # ---- run timeline (samples for the scaling / latency figures) ----

    def _now(self) -> float:
        return time.time() - self._t0 if self._t0 else 0.0

    def _observe(self, decisions: list[Decision]) -> None:
        """Show the decisions, add them to the run's timeline as one batch, and
        give the loads since the last batch the state their window is in now."""
        for i, d in enumerate(decisions):
            self._style_decision(i, d)
        if not self._t0:
            return
        t = self._now()
        batch = [Sample(t, i, d.session_id, d.route, d.pool, d.waiting)
                 for i, d in enumerate(decisions)]
        self._samples.extend(batch)
        states = classify(batch)
        for lt in self._pending_loads:
            if lt.window < len(states):
                lt.state = states[lt.window]
                self._loads.append(lt)
        self._pending_loads = []

    def _mark(self, title: str) -> None:
        if self._t0:
            self._marks.append((self._now(), title))

    def _grab(self, browser: BrowserWidget):
        from ui.page_exploits import ExploitsPage
        pixmap = browser.view.grab()
        if pixmap.isNull() or ExploitsPage._looks_blank(pixmap):  # noqa: SLF001
            fallback = ExploitsPage.screen_grab(browser.view)
            if not fallback.isNull() and not ExploitsPage._looks_blank(fallback):  # noqa: SLF001
                pixmap = fallback
        image = pixmap.toImage()
        image.setDevicePixelRatio(1.0)
        return image

    def _settled_decisions(self, need_sessions: bool) -> list[Decision]:
        """Give the proxy a moment to write its state, then read every
        session's decision (retrying a few times for sessions still missing)."""
        self._spin(1500)
        decisions: list[Decision] = []
        for _ in range(4):
            sids = self._session_ids[:self._count]
            decisions = self._blocking(lambda s=sids: self._fetch_decisions(s))
            if not need_sessions or all(d.session_id for d in decisions):
                break
            self._spin(1000)
        self._observe(decisions)
        return decisions

    def export_report(self) -> None:
        if self._exporting:
            return
        preset = self._preset()
        if preset is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save pool test report", "pool_test_report.pdf", "PDF files (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        if QMessageBox.question(
            self, "Reset test sessions?",
            "The report starts from a clean slate: this machine's own sessions and honeypot "
            "pool assignments are removed first (the same reset as 'Unpoison host IP' on "
            f"the Attack Simulation page), then the {self._count} windows each run their own exploit, "
            "and the run waits for the honeypot pools to scale up to them (a few minutes "
            "per batch of new pools)."
            + (f" The last {self._delayed()} window(s) attack only after pools were pre-built "
               "for them." if self._delayed() else "")
            + (" Between steps, a few random windows clear their own cookies and/or "
               "localStorage, like a visitor clearing their browsing data."
               if self.clear_check.isChecked() else "")
            + " At the end the windows' sessions are released and the pools they no longer "
            "need are scaled down at once (instead of after POOL_IDLE_TIMEOUT_SECONDS)."
            + "\n\nContinue?",
        ) != QMessageBox.StandardButton.Yes:
            return

        self._exporting, self._cancelled = True, False
        self._poll.stop()
        total = 9
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Preparing report...")
        self.cancel_btn.setEnabled(True)
        self.progress_row.setVisible(True)
        for w in (self.export_btn, self.open_all_btn, self.attack_all_btn, self.reset_btn,
                  self.refresh_btn, self.count_spin, self.delayed_spin, self.clear_check):
            w.setEnabled(False)

        error, data = "", None
        try:
            data = self._run_scenario(None, total, preset)
        except Exception as e:  # noqa: BLE001 -- shown to the user below
            error = str(e)

        self.progress_row.setVisible(False)
        for w in (self.export_btn, self.open_all_btn, self.attack_all_btn, self.reset_btn,
                  self.refresh_btn, self.count_spin, self.delayed_spin, self.clear_check):
            w.setEnabled(True)
        self._exporting = False
        self._poll.start()

        if self._cancelled and not error:
            self.pool_label.setText("Report export cancelled.")
            return
        if data is not None and not error:
            self._progress("Rendering PDF...", total - 1, total)
            from core.pool_test_report_pdf import render_pdf
            try:
                verdict = render_pdf(data, path)
            except Exception as e:  # noqa: BLE001
                error = str(e)
        if error:
            self.pool_label.setText(f"✗ Report export failed: {error}")
            QMessageBox.warning(self, "Report export failed", error)
            return
        self.pool_label.setText(f"✓ Report saved: {path} — {verdict.headline}.")
        if QMessageBox.question(
            self, "Report saved", f"Saved pool test report to:\n{path}\n\nOpen it now?",
        ) == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _reset_threat_state(self) -> None:
        """Clean slate, like the exploit report: threat state flushed in Redis AND
        in reverse_proxy's in-process caches (/internal-threat-reset), then this
        machine's sessions and pool assignments removed."""
        import subprocess
        remote = self._remote()
        redis_inspect.flush_threat_state(remote)
        try:
            from core.exploit_report import _load_secret_and_halflife
            secret = _load_secret_and_halflife(target_for("edge", self.state))[0]
            subprocess.run(["curl", "-sk", "-o", "/dev/null", "-H",
                            f"X-Internal-Test-Auth: {secret}",
                            self._base_url() + "/internal-threat-reset"], timeout=15)
        except Exception:  # noqa: BLE001 -- best effort; the unpoison below still runs
            pass
        redis_inspect.clear_local_threat_state(remote)

    def _exploit_queue(self, window: int) -> list:
        """Exploits for one window: its primary and secondary choice, then the
        fallbacks, as presets (those that divert within MAX_ATTEMPTS only)."""
        by_cve = {p.cve: p for p in EXPLOIT_PRESETS}
        plan = window_plan(self._count)[window]
        return [by_cve[c] for c in dict.fromkeys((*plan, *FALLBACK_EXPLOITS)) if c in by_cve]

    def _letter(self, window: int) -> str:
        return FRAMES[window][0][-1]

    # ---- idle windows browse the shop like a shopper would ----

    def _begin_browse(self) -> None:
        self._seen = [[] for _ in range(MAX_WINDOWS)]

    def _browse_url(self, window: int) -> str:
        """Next page for a window that has nothing else to do in this step."""
        path, label = browse_page(window, self._visits[window])
        self._visits[window] += 1
        self._seen[window].append(label)
        return self._base_url() + path

    def _browsed(self, window: int) -> str:
        return browse_action(self._seen[window])

    def _browse_all(self, step: str) -> None:
        """Every window opens its next page."""
        self._load_all([self._browse_url(w) for w in range(len(self.browsers))], step)

    # ---- windows clearing their own browser data ----

    def _clear_browser_data(self, window: int, variant: str, step: int,
                            before: Decision | None) -> ClearEvent:
        """Window `window` clears its own data the way a visitor would from the
        browser's settings: its site storage (from the page, as "clear site
        data" does) and/or every cookie in its profile. Nothing is rewritten."""
        event = ClearEvent(self._now(), window, step, variant,
                           before_session=self._session_ids[window],
                           before_pool=before.pool if before is not None else None)
        browser = self.browsers[window]
        if variant in ("storage", "all") and browser.view.url().toString().startswith("http"):
            got = self._run_js(window, _CLEAR_STORAGE_JS)
            event.storage_keys = int(got) if str(got).isdigit() else 0
        if event.clears_cookies():
            event.cookies = sorted(self._cookie_names[window])
            browser.clear_cookies()
            deadline = time.monotonic() + 3.0      # deleteAllCookies() is asynchronous
            while self._session_ids[window] and time.monotonic() < deadline:
                self._spin(100)
        return event

    def _resolve_cleared(self, cleared: list[ClearEvent], results: list[StepResult]) -> None:
        """Fill in what each clearing led to from the step it happened before,
        and say it in that step's action for the window."""
        for e in cleared:
            if e.step >= len(results):
                continue
            step = results[e.step]
            d = step.decisions[e.window] if e.window < len(step.decisions) else Decision()
            e.after_session, e.after_pool, e.after_route = d.session_id, d.pool, d.route
            e.resolved = True
            if e.window < len(step.actions):
                step.actions[e.window] = (f"First {e.what()} ({e.outcome()}); then "
                                          + step.actions[e.window][:1].lower()
                                          + step.actions[e.window][1:])

    def _attack_step(self, n: int, total_steps: int, total: int, windows: list[int],
                     queues: list[list], used: set[str], runs: list[ExploitRun],
                     title: str, detail: str) -> StepResult:
        """`windows` open their exploit at the same time (up to MAX_ATTEMPTS
        times each) while the others browse the shop. A window whose exploit
        never diverts moves on to the next one in its queue -- so each window
        is guaranteed an exploit that does."""
        self._mark(title)
        self._begin_browse()
        shop = self._base_url() + "/"
        plan = window_plan(self._count)
        state: dict[int, list] = {}     # window -> [preset, attempts, replaced, done]
        tried: dict[int, set[str]] = {}
        for w in windows:
            # Prefer an exploit no other window ran; with many windows they may repeat.
            preset = next((p for p in queues[w] if p.cve not in used), queues[w][0])
            state[w] = [preset, 0, preset.cve != plan[w][0], False]
            tried[w] = {preset.cve}
            used.add(preset.cve)
        last: dict[int, tuple] = {}
        decisions: list[Decision] = []
        while True:
            active = [w for w in windows if not state[w][3]]
            if not active:
                break
            if self._cancelled:
                raise _Cancelled()
            for w in active:
                state[w][1] += 1
            self._progress(f"Step {n}/{total_steps}: " + ", ".join(
                f"{self._letter(w)} attacks with {state[w][0].cve} (attempt {state[w][1]}/{MAX_ATTEMPTS})"
                for w in active), n, total)
            urls = [shop if w in windows else self._browse_url(w)
                    for w in range(len(self.browsers))]
            for w in active:
                urls[w] = self._base_url() + state[w][0].path
            self._load_all(urls, title)
            self._spin(700)
            decisions = self._settled_decisions(need_sessions=True)
            for w in active:
                preset, attempts, replaced, _done = state[w]
                d = decisions[w]
                last[w] = (preset, attempts)
                if d.route == "HONEYPOT":
                    runs.append(ExploitRun(self._letter(w), preset.cve, preset.name, attempts,
                                           True, d.pool, replaced))
                    state[w][3] = True
                elif attempts >= MAX_ATTEMPTS:
                    runs.append(ExploitRun(self._letter(w), preset.cve, preset.name, attempts,
                                           False, d.pool, replaced))
                    nxt = (next((p for p in queues[w] if p.cve not in tried[w] and p.cve not in used), None)
                           or next((p for p in queues[w] if p.cve not in tried[w]), None))
                    if nxt is None:
                        state[w][3] = True
                    else:
                        tried[w].add(nxt.cve)
                        used.add(nxt.cve)
                        state[w] = [nxt, 0, True, False]
        actions = [self._browsed(w) for w in range(len(self.browsers))]
        for w, (preset, attempts) in last.items():
            actions[w] = f"Opens {preset.cve} ({attempts} attempt(s))"
        return StepResult(title, detail, actions, decisions,
                          [self._grab(b) for b in self.browsers], self._read_carts())

    def _wait_for_scaling(self, n: int, total_steps: int, total: int) -> StepResult:
        """Wait until pool_manager has built a pool for every window that is
        still borrowing one (or growth is capped and it never will), then show
        every window on the shop again."""
        title = "Honeypot pools scale up"
        self._mark(title)
        self._begin_browse()
        remote = self._remote()
        before = self._settled_decisions(need_sessions=True)
        start = last_browse = time.monotonic()
        while True:
            if self._cancelled:
                raise _Cancelled()
            sids = self._session_ids[:self._count]
            decisions = self._blocking(lambda s=sids: self._fetch_decisions(s))
            self._observe(decisions)
            try:
                state = self._blocking(lambda: redis_inspect.pool_state(remote))
            except Exception:  # noqa: BLE001 -- keep waiting on the decisions alone
                state = {}
            self._baseline_new_pools(state)
            waiting = [self._letter(i) for i, d in enumerate(decisions) if d.waiting]
            elapsed = int(time.monotonic() - start)
            if not waiting or elapsed >= SCALE_TIMEOUT_S:
                break
            building = ", ".join(sorted((state.get("status") or {}).get("building", {}))) or "none"
            note = f" — growth capped: {state['capped']}" if state.get("capped") else ""
            self._progress(f"Step {n}/{total_steps}: pools scale up — window(s) "
                           f"{', '.join(waiting)} borrow a pool, building pool(s) {building} "
                           f"({elapsed // 60}:{elapsed % 60:02d}){note}", n, total)
            self._spin(2000)
            if time.monotonic() - last_browse >= BROWSE_EVERY_S:
                self._browse_all(title)
                last_browse = time.monotonic()
        self._browse_all(title)
        self._spin(700)
        decisions = self._settled_decisions(need_sessions=True)
        actions = []
        for b, d in zip(before, decisions):
            if b.pool is not None and d.pool is not None and b.pool != d.pool:
                actions.append(f"Moved from borrowed pool {b.pool} to its own pool {d.pool}")
            elif d.waiting:
                actions.append(f"Still borrowing pool {d.pool} (timed out)")
            else:
                actions.append(self._browsed(len(actions)))
        return StepResult(
            title,
            "Windows that found no free pool (not scaled up yet) borrowed a ready one "
            "round-robin while pool_manager built a pool (eshop + seeded database) for each of "
            "them, and must now each be in their own. Once the resource limit is reached no "
            "more pools are built and the remaining windows keep sharing the ready pools "
            "round-robin.",
            actions, decisions, [self._grab(b) for b in self.browsers], self._read_carts())

    def _baseline_new_pools(self, state: dict) -> None:
        """Evidence baseline for pools that became ready during the run, taken
        as soon as they show up (before the windows that will get them attack),
        so the report can show what each of them saw and changed too."""
        new = [p for p in state.get("ready", []) if self._baseline.get("db", {}).get(p) is None]
        if new and self._baseline:
            target = target_for("edge", self.state)
            self._blocking(lambda: pool_evidence.extend_baseline(target, self._baseline, new))

    def _prescale(self, n: int, total_steps: int, total: int, windows: list[int]) -> StepResult:
        """Ask pool_manager for one free pool per delayed window and wait until
        they are ready -- or growth is capped with nothing left building, so
        they never will be. Records how long that took."""
        title = f"Pools pre-built for {len(windows)} delayed window(s)"
        self._mark(title)
        self._begin_browse()
        remote, k = self._remote(), len(windows)
        self._blocking(lambda: redis_inspect.set_pool_reserve(remote, k))
        t_start = self._now()
        reserve = {"requested": k, "start": t_start, "reached": False, "end": None,
                   "free": 0, "reason": ""}
        start = last_browse = time.monotonic()
        try:
            while True:
                if self._cancelled:
                    raise _Cancelled()
                try:
                    state = self._blocking(lambda: redis_inspect.pool_state(remote))
                except Exception:  # noqa: BLE001
                    state = {}
                self._baseline_new_pools(state)
                free = len(state.get("free", []))
                building = (state.get("status") or {}).get("building", {})
                reserve["free"] = free
                elapsed = int(time.monotonic() - start)
                if free >= k:
                    reserve.update(reached=True, end=self._now())
                    break
                if state.get("capped") and not building:
                    reserve.update(end=self._now(), reason=f"growth capped: {state['capped']}")
                    break
                if elapsed >= SCALE_TIMEOUT_S:
                    reserve.update(end=self._now(), reason=f"timed out after {elapsed} s")
                    break
                self._progress(
                    f"Step {n}/{total_steps}: pre-building pools for the delayed windows — "
                    f"{free}/{k} free, building {', '.join(sorted(building)) or 'none'} "
                    f"({elapsed // 60}:{elapsed % 60:02d})"
                    + (f" — growth capped: {state['capped']}" if state.get("capped") else ""),
                    n, total)
                self._spin(2000)
                if time.monotonic() - last_browse >= BROWSE_EVERY_S:
                    self._browse_all(title)
                    last_browse = time.monotonic()
        finally:
            # Stop asking for more: the delayed windows are about to take these.
            self._blocking(lambda: redis_inspect.set_pool_reserve(remote, 0))
        self._reserve = reserve
        self._browse_all(title)
        self._spin(700)
        decisions = self._settled_decisions(need_sessions=True)
        took = (reserve["end"] or self._now()) - t_start
        outcome = (f"{k} free pool(s) ready after {took:.0f} s" if reserve["reached"]
                   else f"only {reserve['free']} of {k} free pool(s) after {took:.0f} s "
                        f"({reserve['reason']})")
        actions = [self._browsed(w) for w in range(len(self.browsers))]
        for w in windows:
            actions[w] = f"{actions[w]} while its pool is built: {outcome}"
        return StepResult(
            title,
            f"Before windows {', '.join(self._letter(w) for w in windows)} attack, the test asks "
            f"pool_manager for {k} free pool(s) and waits until they are ready, so these "
            "windows find a pool of their own the moment they are diverted instead of "
            "borrowing one round-robin. If the resource limit stops the build first, they "
            "share the ready pools round-robin instead.",
            actions, decisions, [self._grab(b) for b in self.browsers], self._read_carts())

    def _forced_scaledown(self, n: int, total_steps: int, total: int,
                          sampler: _UsageSampler) -> dict:
        """End of the run: release the windows' sessions and have pool_manager
        scale down right away, rather than after POOL_IDLE_TIMEOUT_SECONDS,
        sampling resource use before, during and after."""
        remote = self._remote()
        self._progress(f"Step {n}/{total_steps}: forced scale-down — stopping the windows' "
                       "traffic", n, total)
        # No more requests from the windows: one would re-assign its bound session.
        self._load_all(["about:blank"] * len(self.browsers))
        sids = [sid for sid in self._session_ids[:self._count] if sid]
        try:
            before = self._blocking(lambda: redis_inspect.pool_state(remote))
        except Exception:  # noqa: BLE001
            before = {}
        sampler.interval = 3.0
        self._spin(4000)                    # a resource sample just before
        requested = self._now()
        self._blocking(lambda: redis_inspect.request_scaledown(remote, sids))
        start, state, done = time.monotonic(), before, None
        while True:
            if self._cancelled:
                raise _Cancelled()
            self._spin(2000)
            try:
                state = self._blocking(lambda: redis_inspect.pool_state(remote))
            except Exception:  # noqa: BLE001
                continue
            elapsed = int(time.monotonic() - start)
            if not state.get("scaledown_pending"):
                done = self._now()
                break
            if elapsed >= SCALEDOWN_TIMEOUT_S:
                break
            self._progress(f"Step {n}/{total_steps}: forced scale-down — {len(state.get('ready', []))} "
                           f"pool(s) left ({elapsed // 60}:{elapsed % 60:02d})", n, total)
        self._spin(8000)                    # resource samples after the removal
        try:
            state = self._blocking(lambda: redis_inspect.pool_state(remote))
        except Exception:  # noqa: BLE001
            pass
        for i, browser in enumerate(self.browsers):   # later manual use starts afresh
            browser.clear_cookies()
            self._session_ids[i] = ""
            self._style_decision(i, Decision())
        status = (before.get("status") or {}) if before else {}
        return {"requested": requested, "done": done, "sessions": len(sids),
                "pools_before": before.get("ready", []) if before else [],
                "building_before": sorted(int(n) for n in status.get("building", {})),
                "pools_after": state.get("ready", []) if state else [],
                "idle_timeout": status.get("idle_timeout"), "spares": status.get("spares"),
                "mem_per_pool": status.get("mem_per_pool"),
                "cpus_per_pool": status.get("cpus_per_pool")}

    def _run_scenario(self, total_unused, _total, preset) -> PoolTestData | None:
        remote, target = self._remote(), target_for("edge", self.state)
        count, delayed = self._count, self._delayed()
        now_windows = list(range(count - delayed))
        later_windows = list(range(count - delayed, count))
        cart_plan = CART_PLAN[:count]
        plan = window_plan(count)
        # open, fill carts, one attack per immediate window, scale-up, [pre-build,
        # delayed attack, scale-up], second exploit, cart page
        total_steps = 2 + len(now_windows) + (1 if now_windows else 0) \
            + (3 if later_windows else 0) + 2 + 1      # ... + forced scale-down
        total = total_steps + 3
        self._progress("Resetting test sessions...", 0, total)
        self._blocking(self._reset_threat_state)
        for i, browser in enumerate(self.browsers):
            browser.clear_cookies()
            self._session_ids[i] = ""
            self._style_decision(i, Decision())
        self._load_all(["about:blank"] * len(self.browsers))
        self._spin(500)

        try:
            ready = self._blocking(lambda: redis_inspect.pool_state(remote)).get("ready", [])
        except Exception:  # noqa: BLE001
            ready = []
        baseline = self._blocking(lambda: pool_evidence.take_baseline(target, ready))
        self._baseline = baseline
        # The run's clock starts here; pool_manager's events carry the edge
        # host's clock, so remember how far Redis' clock is from ours.
        try:
            offset = self._blocking(lambda: redis_inspect.server_time(remote)) - time.time()
        except Exception:  # noqa: BLE001 -- same host: no offset
            offset = 0.0
        self._t0 = time.time()
        self._samples, self._loads, self._pending_loads, self._marks = [], [], [], []
        self._reserve = {}
        self._visits = [0] * MAX_WINDOWS
        sampler = _UsageSampler(target, self._t0, self)
        sampler.start()
        try:
            return self._run_steps(remote, target, baseline, offset, sampler, count, delayed,
                                   now_windows, later_windows, cart_plan, plan, total_steps, total)
        finally:
            sampler.stop()
            sampler.wait(30000)
            self._t0 = 0.0

    def _run_steps(self, remote, target, baseline, offset, sampler, count, delayed,
                   now_windows, later_windows, cart_plan, plan, total_steps, total):

        shop = self._base_url() + "/"
        results: list[StepResult] = []
        runs: list[ExploitRun] = []
        used: set[str] = set()
        step = 0
        # Clearing starts once every window has filled its cart (step 3) and can
        # happen before any later step up to the cart page; never the scale-down.
        clear_seed = random.randrange(2 ** 31) if self.clear_check.isChecked() else None
        schedule = clear_schedule(list(range(3, total_steps)), count,
                                  random.Random(clear_seed)) if clear_seed is not None else {}
        cleared: list[ClearEvent] = []

        def next_step(label: str) -> int:
            nonlocal step
            step += 1
            for w, variant in schedule.get(step, []):
                self._progress(f"Step {step}/{total_steps}: {FRAMES[w][0]} clears its browser data",
                               step, total)
                before = results[-1].decisions[w] if results and w < len(results[-1].decisions) else None
                cleared.append(self._clear_browser_data(w, variant, len(results), before))
            self._progress(f"Step {step}/{total_steps}: {label}", step, total)
            return step

        try:
            next_step("all windows open the shop")
            self._mark("All windows open the shop")
            self._load_all([shop] * len(self.browsers), "All windows open the shop")
            self._spin(700)
            decisions = self._settled_decisions(need_sessions=True)
            results.append(StepResult(
                "All windows open the shop", f"{count} new sessions, all routed to production.",
                ["Browses the shop"] * len(self.browsers), decisions,
                [self._grab(b) for b in self.browsers], self._read_carts()))

            # Every window fills its own cart, while still on production.
            next_step("every window fills its cart")
            self._mark("Every window fills its cart")
            slugs = sorted({slug for items in cart_plan for slug, _q in items})
            ids = parse_product_ids(self._run_js(0, product_ids_js(slugs)), slugs)
            self._begin_browse()
            for k in range(max(len(items) for items in cart_plan)):
                urls = [f"{self._base_url()}/?add-to-cart={ids[items[k][0]]}&quantity={items[k][1]}"
                        if k < len(items) else self._browse_url(w) for w, items in enumerate(cart_plan)]
                self._load_all(urls, "Every window fills its cart")
                self._spin(500)
            decisions = self._settled_decisions(need_sessions=True)
            results.append(StepResult(
                "Every window fills its cart",
                "Each window adds its own products. These carts are the baseline: they must "
                "look exactly the same after the session is routed to a honeypot pool.",
                ["Adds " + ", ".join(f"{slug} \u00d7 {q}" for slug, q in items)
                 + (", then looks at " + ", ".join(dict.fromkeys(self._seen[w])) if self._seen[w] else "")
                 for w, items in enumerate(cart_plan)],
                decisions, [self._grab(b) for b in self.browsers], self._read_carts()))

            queues = [self._exploit_queue(i) for i in range(count)]
            for w in now_windows:
                n = next_step(f"{FRAMES[w][0]} attacks")
                first = next((p for p in queues[w] if p.cve not in used), queues[w][0])
                results.append(self._attack_step(
                    n, total_steps, total, [w], queues, used, runs,
                    f"{FRAMES[w][0]} attacks with {first.cve}",
                    f"{first.name}. The session must be bound to a pool no other window has -- "
                    "or, when no pool is free yet, borrow one round-robin until the pool being "
                    "built for it is ready -- and the windows that have not attacked yet must "
                    "stay on production."))

            if now_windows:
                results.append(self._wait_for_scaling(next_step("pools scale up"), total_steps, total))

            if later_windows:
                results.append(self._prescale(next_step("pre-building pools for the delayed windows"),
                                              total_steps, total, later_windows))
                letters = ", ".join(self._letter(w) for w in later_windows)
                results.append(self._attack_step(
                    next_step(f"delayed windows {letters} attack"), total_steps, total,
                    later_windows, queues, used, runs,
                    f"Delayed windows {letters} attack together",
                    "These windows attack only now that pools were built for them: each must get "
                    "a free pool of its own at once (no borrowing) -- unless the resource limit "
                    "stopped the build, in which case they share the ready pools round-robin."))
                results.append(self._wait_for_scaling(next_step("pools scale up"), total_steps, total))

            # Every window runs a SECOND exploit it has not run yet, all at once.
            next_step("all windows run a second exploit")
            self._mark("All windows run a second exploit")
            self._begin_browse()
            by_cve = {p.cve: p for p in EXPLOIT_PRESETS}
            second = []
            for w in range(count):
                own = {r.cve for r in runs if r.window == self._letter(w)}
                second.append(next((by_cve[c] for c in (plan[w][1], *FALLBACK_EXPLOITS)
                                    if c in by_cve and c not in own), None))
            self._load_all([self._base_url() + p.path if p else self._browse_url(w)
                            for w, p in enumerate(second)], "All windows run a second exploit")
            self._spin(700)
            decisions = self._settled_decisions(need_sessions=True)
            for i, d in enumerate(decisions):
                if second[i]:
                    runs.append(ExploitRun(self._letter(i), second[i].cve, second[i].name, 1,
                                           d.route == "HONEYPOT", d.pool))
            results.append(StepResult(
                "All windows run a second exploit",
                "Sticky binding: each second exploit must land in the pool the window already "
                "owns, nobody changes pool, nobody is merged.",
                [f"Opens {p.cve}" if p else self._browsed(w) for w, p in enumerate(second)], decisions,
                [self._grab(b) for b in self.browsers], self._read_carts()))

            # Last step: open the cart page in every window -- what a shopper would see.
            next_step("every window opens its cart")
            self._mark("Every window opens its cart")
            self._load_all([self._base_url() + "/cart/"] * len(self.browsers),
                           "Every window opens its cart")
            self._spin(2500)   # the block cart renders from the Store API after load
            decisions = self._settled_decisions(need_sessions=True)
            results.append(StepResult(
                "Every window opens its cart",
                "The cart page, served by each window's honeypot pool, must show the same "
                "products and quantities that were added on production.",
                ["Opens the cart page"] * len(self.browsers), decisions,
                [self._grab(b) for b in self.browsers], self._read_carts()))
        except _Cancelled:
            return None
        self._resolve_cleared(cleared, results)

        # Evidence and the registry first: the scale-down removes containers.
        self._progress("Reading what each honeypot container saw...", total - 2, total)
        try:
            pool_state = self._blocking(lambda: redis_inspect.pool_state(remote))
        except Exception:  # noqa: BLE001 -- the report says the state was unreadable
            pool_state = {}
        final = results[-1].decisions
        pools = list(dict.fromkeys(d.pool for d in final if d.pool is not None))
        pools += [n for n in pool_state.get("ready", []) if n not in pools][:max(0, count + 3 - len(pools))]
        evidence = self._blocking(lambda: pool_evidence.collect(target, pools, baseline))
        frames = [FrameResult(
            label=FRAMES[i][0], user_agent=b.profile.httpUserAgent(),
            language=b.profile.httpAcceptLanguage(), url=b.view.url().toString(),
            session_id=final[i].session_id, pool=final[i].pool,
            screenshot=results[-1].shots[i]) for i, b in enumerate(self.browsers)]

        try:
            scaledown = self._forced_scaledown(step + 1, total_steps, total, sampler)
        except _Cancelled:
            return None
        duration = self._now()
        try:
            raw_events = self._blocking(lambda: redis_inspect.pool_events(remote))
        except Exception:  # noqa: BLE001 -- the latency section says so
            raw_events = []
        t0 = time.time() - duration
        events = []
        for e in raw_events:
            at = float(e["at"]) - offset - t0
            if at < -5 or at > duration + 5:
                continue
            e = dict(e, at=at)
            if "start" in e:
                e["start"] = float(e["start"]) - offset - t0
            events.append(e)
        return PoolTestData(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_label=target.label, base_url=self._base_url(),
            exploit=", ".join(f"{r.window}: {r.cve}" for r in runs), frames=frames,
            pool_state=pool_state, steps=results, runs=runs, evidence=evidence,
            since=baseline.get("since", ""), duration=duration, delayed=delayed,
            samples=list(self._samples), loads=list(self._loads), events=events,
            marks=list(self._marks), reserve=dict(self._reserve),
            usage=list(sampler.samples), scaledown=scaledown,
            cleared=cleared, clear_seed=clear_seed)

    def reset_sessions(self) -> None:
        for browser in self.browsers:
            browser.clear_cookies()
            browser.navigate("about:blank")

    def refresh_pool_state(self) -> None:
        """Read the pool registry off the GUI thread (a stopped stack makes the
        docker call slow, and this runs every time the page is shown)."""
        if self._exporting or getattr(self, "_pool_job", None) is not None:
            return
        remote = self._remote()
        job = _Job(lambda: redis_inspect.pool_state(remote), self)
        self._pool_job = job

        def done() -> None:
            self._pool_job = None
            if not self._exporting:
                if job.error is not None:
                    self.pool_label.setText(f"Pool state unavailable: {job.error}")
                else:
                    info = job.result
                    owners = ", ".join(f"pool {n}: {c} session(s)"
                                       for n, c in sorted(info["owners"].items()))
                    text = f"Ready pools: {info['ready'] or 'none'} — owners: {owners or 'none'}"
                    status = info.get("status") or {}
                    if status:
                        building = ", ".join(sorted(status.get("building", {})))
                        text += (f" — room for {status.get('room', '?')} more pool(s) under the "
                                 "resource limit" + (f", building {building}" if building else ""))
                    if info.get("waiting"):
                        text += (f" — scaling up: {info['waiting']} session(s) borrow a pool "
                                 "until theirs is built")
                    if info["capped"]:
                        text += (f" — pool growth capped: {info['capped']} (further sessions "
                                 "share the ready pools round-robin)")
                    self.pool_label.setText(text)
            job.deleteLater()
        job.finished.connect(done)
        job.start()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.refresh_pool_state()
        self._poll.start()

    def hideEvent(self, event) -> None:
        super().hideEvent(event)
        if not self._exporting:
            self._poll.stop()
