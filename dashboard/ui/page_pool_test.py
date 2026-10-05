"""Pool test page: three embedded browsers, each its own attacker session,
to see how the honeypot pool receives several attackers at once.

Every frame is a BrowserWidget, i.e. its own off-the-record profile and so its
own cookie jar -- the proxy hands each one a separate signed session cookie.
Cookies alone are not enough, though: a request that arrives WITHOUT a cookie
is matched to an existing session by a passive fingerprint (TLS hello,
User-Agent, Accept-Language, client IP; see session_identity_rules.lua), and
three frames of one app on one machine would otherwise share all of it, so the
second and third frames would be folded into the first frame's session. Each
frame therefore gets its own User-Agent suffix and Accept-Language, which is
what makes the proxy see three different clients.

"Attack" sends the same exploit request from the frame; once the score tips,
the session is bound to a honeypot pool. The pool summary (from the Redis
pool registry) shows how many pools are ready and how many sessions each owns.
"""
from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import QEventLoop, Qt, QThread, QTimer, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QLabel, QMessageBox,
    QProgressBar, QPushButton, QSplitter, QVBoxLayout, QWidget,
)

from core import redis_inspect
from core.docker_ctl import target_for
from core.exploits import EXPLOIT_PRESETS
from core import pool_evidence
from core.pool_test_report import (EXPLOIT_PLAN, FALLBACK_EXPLOITS, MAX_ATTEMPTS, Decision,
                                    ExploitRun, FrameResult, PoolTestData, StepResult,
                                    parse_decision)
from core.state import AppState
from ui.browser_widget import BrowserWidget

# Name of the proxy's session cookie (init.lua: session.cookie_name).
SESSION_COOKIE = "SERVERID"

# (label, Accept-Language) per frame -- what makes the fingerprints differ.
FRAMES = [
    ("Attacker A", "en-US,en;q=0.9"),
    ("Attacker B", "de-DE,de;q=0.9"),
    ("Attacker C", "fr-FR,fr;q=0.9"),
]


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
        title = QLabel("Pool test")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(title)

        intro = QLabel(
            "Three browsers, three separate sessions (own cookies, own User-Agent and "
            "language, so the proxy cannot merge them). Open the shop in each, then attack "
            "from several at once and check that every attacker lands in a honeypot pool "
            "of their own.")
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #aaaaaa;")
        layout.addWidget(intro)

        bar = QHBoxLayout()
        self.preset_combo = QComboBox()
        for p in self._presets:
            self.preset_combo.addItem(f"{p.cve} — {p.name}")
        self.preset_combo.setMinimumWidth(320)
        bar.addWidget(QLabel("Exploit:"))
        bar.addWidget(self.preset_combo, stretch=1)
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
        self.export_btn = QPushButton("Export report (PDF)")
        self.export_btn.setToolTip(
            "Which honeypot pool each window's session landed in, and whether that matches "
            "one attacker per pool (shared only when pools run out).")
        self.export_btn.clicked.connect(self.export_report)
        bar.addWidget(self.export_btn)
        layout.addLayout(bar)

        # In-page progress row (not a floating dialog, so it can never land in
        # the frames' screenshots) -- same pattern as the Exploits page.
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

        self.pool_label = QLabel("")
        self.pool_label.setWordWrap(True)
        self.refresh_btn = QPushButton("Refresh pool state")
        self.refresh_btn.clicked.connect(self.refresh_pool_state)
        row = QHBoxLayout()
        row.addWidget(self.pool_label, stretch=1)
        row.addWidget(self.refresh_btn)
        layout.addLayout(row)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.browsers: list[BrowserWidget] = []
        # Per frame: the session id from the SERVERID cookie the proxy set it
        # ("<id>.<mac>"), kept up to date from the profile's cookie store.
        self._session_ids = [""] * len(FRAMES)
        self.decision_labels: list[QLabel] = []
        for i, (label, _lang) in enumerate(FRAMES):
            browser = BrowserWidget()
            ua, lang = frame_identity(browser.profile.httpUserAgent(), i)
            browser.profile.setHttpUserAgent(ua)
            browser.profile.setHttpAcceptLanguage(lang)
            self.browsers.append(browser)
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
            self.decision_labels.append(decision)
            self._style_decision(i, Decision())
            splitter.addWidget(box)
        layout.addWidget(splitter, stretch=1)

        # Keeps the labels under the frames current while browsing by hand.
        self._poll = QTimer(self)
        self._poll.setInterval(3000)
        self._poll.timeout.connect(self.refresh_decisions)

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
        if bytes(cookie.name()).decode(errors="replace") == SESSION_COOKIE:
            value = bytes(cookie.value()).decode(errors="replace")
            self._session_ids[index] = value.split(".", 1)[0]

    def _on_cookie_removed(self, index: int, cookie) -> None:
        if bytes(cookie.name()).decode(errors="replace") == SESSION_COOKIE:
            self._session_ids[index] = ""

    # ---- routing decision under each frame ----

    def _style_decision(self, index: int, d: Decision) -> None:
        color = {"HONEYPOT": "#e08a00", "PRODUCTION": "#5cb85c"}.get(d.route, "#777777")
        label = self.decision_labels[index]
        label.setText(d.text())
        label.setStyleSheet(
            f"QLabel {{ background-color: {color}; color: #1e1e1e; padding: 4px 10px; "
            "border-radius: 4px; font-weight: bold; }")

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
                raw, pool = redis_inspect.session_decision_raw(remote, sid)
                out.append(parse_decision(sid, raw, pool))
            return out
        return read()

    def refresh_decisions(self) -> None:
        """Async refresh of the labels (skipped while a read or an export runs)."""
        if self._exporting or self._job is not None or not self.isVisible():
            return
        sids = list(self._session_ids)
        job = _Job(lambda: self._fetch_decisions(sids), self)
        self._job = job

        def done() -> None:
            self._job = None
            if job.error is None and not self._exporting:
                for i, d in enumerate(job.result or []):
                    self._style_decision(i, d)
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

    # ---- report export (progress bar, all three frames move every step) ----

    def _cancel_report(self) -> None:
        self._cancelled = True
        self.cancel_btn.setEnabled(False)
        self.progress_label.setText("Cancelling...")

    def _progress(self, message: str, current: int, total: int) -> None:
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.progress_label.setText(message)

    def _load_all(self, urls: list[str]) -> None:
        """Navigate each frame to its URL and wait for all loads (hard timeout,
        so one stuck page cannot hang the export)."""
        # A frame already on about:blank never fires loadFinished for about:blank.
        pending = {i for i, u in enumerate(urls)
                   if not (u == "about:blank" and self.browsers[i].view.url().toString()
                           in ("", "about:blank"))}
        loop = QEventLoop()
        if not pending:
            for browser, url in zip(self.browsers, urls):
                browser.navigate(url)
            return
        conns = []
        for i, (browser, url) in enumerate(zip(self.browsers, urls)):
            def finished(_ok, n=i):
                pending.discard(n)
                if not pending:
                    loop.quit()
            conns.append((browser, browser.view.loadFinished.connect(finished)))
            browser.navigate(url)
        QTimer.singleShot(9000, loop.quit)
        loop.exec()
        for browser, conn in conns:
            try:
                browser.view.loadFinished.disconnect(conn)
            except TypeError:
                pass

    def _grab(self, browser: BrowserWidget):
        from ui.page_exploits import ExploitsPage
        pixmap = browser.view.grab()
        if pixmap.isNull() or ExploitsPage._looks_blank(pixmap):  # noqa: SLF001
            handle = self.window().windowHandle()
            screen = handle.screen() if handle else QApplication.primaryScreen()
            if screen is not None:
                fallback = screen.grabWindow(int(browser.view.winId()))
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
            sids = list(self._session_ids)
            decisions = self._blocking(lambda s=sids: self._fetch_decisions(s))
            if not need_sessions or all(d.session_id for d in decisions):
                break
            self._spin(1000)
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
            "the Exploits page), then the three windows each run a different exploit.\n\nContinue?",
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
                  self.refresh_btn):
            w.setEnabled(False)

        error, data = "", None
        try:
            data = self._run_scenario(None, total, preset)
        except Exception as e:  # noqa: BLE001 -- shown to the user below
            error = str(e)

        self.progress_row.setVisible(False)
        for w in (self.export_btn, self.open_all_btn, self.attack_all_btn, self.reset_btn,
                  self.refresh_btn):
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
        return [by_cve[c] for c in (*EXPLOIT_PLAN[window], *FALLBACK_EXPLOITS) if c in by_cve]

    def _attack_step(self, n: int, total_steps: int, window: int, queue: list,
                     used: set[str], runs: list[ExploitRun]) -> StepResult:
        """Window `window` opens its exploit (up to MAX_ATTEMPTS times) while the
        others browse the shop. If the exploit never diverts, the next one in the
        queue is tried -- so the window is guaranteed an exploit that does."""
        label = FRAMES[window][0]
        shop = self._base_url() + "/"
        preset = next(p for p in queue if p.cve not in used)
        replaced = preset.cve != EXPLOIT_PLAN[window][0]
        decisions: list[Decision] = []
        while True:
            used.add(preset.cve)
            attempts = 0
            while attempts < MAX_ATTEMPTS:
                if self._cancelled:
                    raise _Cancelled()
                attempts += 1
                self._progress(f"Step {n}/{total_steps}: {label} attacks with {preset.cve} "
                               f"(attempt {attempts}/{MAX_ATTEMPTS})", n, total_steps + 3)
                urls = [shop] * len(self.browsers)
                urls[window] = self._base_url() + preset.path
                self._load_all(urls)
                self._spin(700)
                decisions = self._settled_decisions(need_sessions=True)
                for i, d in enumerate(decisions):
                    self._style_decision(i, d)
                if decisions[window].route == "HONEYPOT":
                    break
            diverted = decisions[window].route == "HONEYPOT"
            runs.append(ExploitRun(label[-1], preset.cve, preset.name, attempts, diverted,
                                   decisions[window].pool, replaced))
            if diverted:
                break
            nxt = [p for p in queue if p.cve not in used]
            if not nxt:
                break
            preset, replaced = nxt[0], True
        actions = ["Browses the shop"] * len(self.browsers)
        actions[window] = f"Opens {preset.cve} ({attempts} attempt(s))"
        return StepResult(f"{label} attacks with {preset.cve}",
                          f"{preset.name}. The session must be bound to a pool no other "
                          "window has, and the others must stay on production.",
                          actions, decisions, [self._grab(b) for b in self.browsers])

    def _run_scenario(self, total_unused, _total, preset) -> PoolTestData | None:
        remote, target = self._remote(), target_for("edge", self.state)
        total_steps = 6
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

        shop = self._base_url() + "/"
        results: list[StepResult] = []
        runs: list[ExploitRun] = []
        used: set[str] = set()
        try:
            self._progress(f"Step 1/{total_steps}: all windows open the shop", 1, total)
            self._load_all([shop] * len(self.browsers))
            self._spin(700)
            decisions = self._settled_decisions(need_sessions=True)
            for i, d in enumerate(decisions):
                self._style_decision(i, d)
            results.append(StepResult(
                "All windows open the shop", "Three new sessions, all routed to production.",
                ["Browses the shop"] * len(self.browsers), decisions,
                [self._grab(b) for b in self.browsers]))

            queues = [self._exploit_queue(i) for i in range(len(self.browsers))]
            for w in range(len(self.browsers)):
                results.append(self._attack_step(w + 2, total_steps, w, queues[w], used, runs))

            # Final step: every window runs a SECOND, different exploit at once.
            self._progress(f"Step {total_steps}/{total_steps}: all windows run a second exploit",
                           total_steps, total)
            by_cve = {p.cve: p for p in EXPLOIT_PRESETS}
            second = []
            for w in range(len(self.browsers)):
                pick = next((by_cve[c] for c in (EXPLOIT_PLAN[w][1], *FALLBACK_EXPLOITS)
                             if c in by_cve and c not in used), None)
                second.append(pick)
                if pick:
                    used.add(pick.cve)
            self._load_all([self._base_url() + p.path if p else shop for p in second])
            self._spin(700)
            decisions = self._settled_decisions(need_sessions=True)
            for i, d in enumerate(decisions):
                self._style_decision(i, d)
                if second[i]:
                    runs.append(ExploitRun(FRAMES[i][0][-1], second[i].cve, second[i].name, 1,
                                           d.route == "HONEYPOT", d.pool))
            results.append(StepResult(
                "All windows run a second exploit",
                "Sticky binding: each second exploit must land in the pool the window already "
                "owns, nobody changes pool, nobody is merged.",
                [f"Opens {p.cve}" if p else "Browses the shop" for p in second], decisions,
                [self._grab(b) for b in self.browsers]))
        except _Cancelled:
            return None

        self._progress("Reading what each honeypot container saw...", total - 2, total)
        try:
            pool_state = self._blocking(lambda: redis_inspect.pool_state(remote))
        except Exception:  # noqa: BLE001 -- the report says the state was unreadable
            pool_state = {}
        final = results[-1].decisions
        pools = [d.pool for d in final if d.pool is not None]
        pools += [n for n in pool_state.get("ready", []) if n not in pools][:max(0, 6 - len(pools))]
        evidence = self._blocking(lambda: pool_evidence.collect(target, pools, baseline))
        frames = [FrameResult(
            label=FRAMES[i][0], user_agent=b.profile.httpUserAgent(),
            language=b.profile.httpAcceptLanguage(), url=b.view.url().toString(),
            session_id=final[i].session_id, pool=final[i].pool,
            screenshot=results[-1].shots[i]) for i, b in enumerate(self.browsers)]
        return PoolTestData(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_label=target.label, base_url=self._base_url(),
            exploit=", ".join(f"{r.window}: {r.cve}" for r in runs), frames=frames,
            pool_state=pool_state, steps=results, runs=runs, evidence=evidence,
            since=baseline.get("since", ""))

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
                    if info["capped"]:
                        text += f" — pool growth capped: {info['capped']}"
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
