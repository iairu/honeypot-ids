"""Full-page screenshots of every SIEM Analytics page button, for the Kibana PDF
export (core/kibana_report.py).

Captures run in a separate, never-shown QWebEngineView that shares the Kibana
page's own QWebEngineProfile -- so it rides on the same login cookies and the
user's view isn't navigated away or resized. Each page is loaded fresh
(via about:blank, so two dashboards that differ only by URL fragment still
get a full load), left to settle until Kibana reports its panels rendered,
then the view is resized to the page's full scroll height and grabbed.

Kibana is a React SPA: loadFinished fires on the near-empty shell long
before the panels have data, so "settled" is polled from the page itself
(no loading indicators / spinners left, every panel's data-render-complete
true) rather than guessed with a fixed delay.
"""
from __future__ import annotations

import json
import time

from PyQt6.QtCore import QObject, QTimer, QUrl, Qt, pyqtSignal
from PyQt6.QtWebEngineCore import QWebEngineCertificateError, QWebEnginePage, QWebEngineProfile
from PyQt6.QtWebEngineWidgets import QWebEngineView

from core.kibana_report import KibanaShot

CAPTURE_WIDTH = 1400
_VIEWPORT_HEIGHT = 900
# Chromium's max texture size is 16384px; stay well below it.
_MAX_HEIGHT = 12000
_POLL_MS = 500
_MIN_SETTLE_S = 2.5
_LOAD_TIMEOUT_S = 45.0
_SETTLE_TIMEOUT_S = 30.0

# Returns {"busy": bool, "h": full content height}. Inner scroll containers
# count too -- their hidden overflow is added to the viewport height, since
# growing the viewport by that much is what un-scrolls them.
_PROBE_JS = r"""
(function() {
    var sel = '[data-render-complete="false"], .euiLoadingChart, .euiLoadingSpinner, '
            + '.euiLoadingContent, .euiSkeletonRectangle, .kbnLoadingIndicator, '
            + '[data-test-subj="globalLoadingIndicator"]';
    var busy = document.readyState !== 'complete' || document.querySelectorAll(sel).length > 0;
    var root = document.documentElement, body = document.body;
    var h = Math.max(root.scrollHeight, body ? body.scrollHeight : 0, window.innerHeight);
    var all = body ? body.getElementsByTagName('*') : [];
    for (var i = 0; i < all.length; i++) {
        var el = all[i];
        var extra = el.scrollHeight - el.clientHeight;
        if (extra > 4 && el.clientHeight > 100) {
            var oy = window.getComputedStyle(el).overflowY;
            if (oy === 'auto' || oy === 'scroll') {
                h = Math.max(h, window.innerHeight + extra);
            }
        }
    }
    return JSON.stringify({busy: busy, h: h});
})();
"""


class KibanaCapture(QObject):
    """Captures ``[(label, path)]`` under ``base_url`` one after another.
    Emits ``progress(index, label)`` before each page and ``done(shots)`` at
    the end (also after cancel(), with whatever was captured so far)."""

    progress = pyqtSignal(int, str)
    done = pyqtSignal(list)

    def __init__(self, profile: QWebEngineProfile, base_url: str, pages: list[tuple[str, str]],
                 autologin_js: str | None = None, parent=None):
        super().__init__(parent)
        self._base = base_url.rstrip("/")
        self._pages = list(pages)
        self._autologin_js = autologin_js
        self._shots: list[KibanaShot] = []
        self._index = -1
        self._cancelled = False
        self._phase = "idle"
        self._login_tried = False
        self._started = 0.0
        self._quiet_polls = 0
        self._target_h = _VIEWPORT_HEIGHT

        self._page = QWebEnginePage(profile, self)
        self._page.certificateError.connect(self._on_cert_error)
        self._view = QWebEngineView()
        self._view.setPage(self._page)
        # Rendered (so grab() has pixels) but never shown on screen.
        self._view.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
        self._view.resize(CAPTURE_WIDTH, _VIEWPORT_HEIGHT)
        self._view.show()
        self._view.loadFinished.connect(self._on_load_finished)

        self._timer = QTimer(self)
        self._timer.setInterval(_POLL_MS)
        self._timer.timeout.connect(self._tick)

    # ---- control ----

    def start(self) -> None:
        self._next()

    def cancel(self) -> None:
        self._cancelled = True
        self._finish()

    def _next(self) -> None:
        if self._cancelled:
            return
        self._index += 1
        if self._index >= len(self._pages):
            self._finish()
            return
        label, _path = self._pages[self._index]
        self.progress.emit(self._index, label)
        self._login_tried = False
        self._view.resize(CAPTURE_WIDTH, _VIEWPORT_HEIGHT)
        self._phase = "blank"
        self._view.load(QUrl("about:blank"))

    def _finish(self) -> None:
        if self._phase == "finished":
            return
        self._phase = "finished"
        self._timer.stop()
        self._view.stop()
        self._view.deleteLater()
        self.done.emit(self._shots)

    def _record(self, image=None, error: str = "") -> None:
        label, path = self._pages[self._index]
        self._shots.append(KibanaShot(label, path, self._base + path, image, error))
        self._timer.stop()
        QTimer.singleShot(0, self._next)

    # ---- loading ----

    def _on_cert_error(self, error: QWebEngineCertificateError) -> None:
        # Kibana uses this repo's self-signed cert (see browser_widget.py).
        error.acceptCertificate()

    def _on_load_finished(self, ok: bool) -> None:
        if self._phase == "blank":
            _label, path = self._pages[self._index]
            self._phase = "loading"
            self._started = time.monotonic()
            self._timer.start()
            self._view.load(QUrl(self._base + path))
            return
        if self._phase not in ("loading", "settling"):
            return
        if not ok:
            # A failed sub-navigation during an SPA redirect can report
            # False; only give up via the timeout in _tick.
            return
        if self._view.url().path() == "/login":
            if self._autologin_js and not self._login_tried:
                self._login_tried = True
                self._page.runJavaScript(self._autologin_js)
            return
        self._phase = "settling"
        self._started = time.monotonic()
        self._quiet_polls = 0

    def _tick(self) -> None:
        if self._cancelled or self._phase == "finished":
            return
        elapsed = time.monotonic() - self._started
        if self._phase == "loading":
            if elapsed > _LOAD_TIMEOUT_S:
                why = ("stuck on the Kibana login page (not logged in)"
                       if self._view.url().path() == "/login" else "the page did not load")
                self._record(error=why)
            return
        if self._phase in ("settling", "grow"):
            self._page.runJavaScript(_PROBE_JS, self._on_probe)

    def _on_probe(self, result) -> None:
        if self._phase not in ("settling", "grow"):
            return
        try:
            info = json.loads(result) if isinstance(result, str) else {}
        except ValueError:
            info = {}
        busy = bool(info.get("busy", True))
        height = int(info.get("h", _VIEWPORT_HEIGHT) or _VIEWPORT_HEIGHT)
        elapsed = time.monotonic() - self._started
        self._quiet_polls = 0 if busy else self._quiet_polls + 1
        ready = (self._quiet_polls >= 2 and elapsed >= _MIN_SETTLE_S) or elapsed > _SETTLE_TIMEOUT_S

        if self._phase == "settling" and ready:
            # Grow the viewport to the whole page, then let it re-lay-out
            # (charts re-render at the new size) before grabbing.
            self._target_h = max(_VIEWPORT_HEIGHT, min(height, _MAX_HEIGHT))
            self._view.resize(CAPTURE_WIDTH, self._target_h)
            self._phase = "grow"
            self._started = time.monotonic()
            self._quiet_polls = 0
            return
        if self._phase == "grow" and ready:
            grown = max(_VIEWPORT_HEIGHT, min(height, _MAX_HEIGHT))
            if grown > self._target_h + 8 and elapsed <= _SETTLE_TIMEOUT_S:
                # Content grew with the viewport (lazy panels) -- once more.
                self._target_h = grown
                self._view.resize(CAPTURE_WIDTH, grown)
                self._started = time.monotonic()
                self._quiet_polls = 0
                return
            img = self._view.grab().toImage()
            if img.isNull():
                self._record(error="the screenshot came back empty")
            else:
                self._record(image=img)
