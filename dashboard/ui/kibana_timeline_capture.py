"""Screenshots of the exploit report's Kibana request timeline
(core/kibana_timeline.py), one per exploit.

A never-shown QWebEngineView on its own profile logs in to Kibana once (same
autologin script as the SIEM Analytics page), imports the timeline's saved objects
through Kibana's own API with that session, then for each capture loads the
one-panel dashboard in embed mode for the exploit's time window, waits until
Kibana reports the panel rendered, and grabs just the panel.

Everything is asynchronous on the GUI thread; capture() calls ``done(path)``
when finished ("" on any failure, so the report simply leaves the image out).
"""
from __future__ import annotations

import json
import time

from PyQt6.QtCore import QObject, QRect, QTimer, QUrl, Qt
from PyQt6.QtWebEngineCore import QWebEngineCertificateError, QWebEnginePage, QWebEngineProfile
from PyQt6.QtWebEngineWidgets import QWebEngineView

from core import kibana_timeline

CAPTURE_WIDTH = 1400
_VIEWPORT_HEIGHT = 600
_POLL_MS = 400
_MIN_SETTLE_S = 1.5
_TIMEOUT_S = 45.0

# Ready once the dashboard's panel exists and reports its chart rendered (the
# bare "Loading Elastic" shell has neither), with no loading indicator left.
_READY_JS = r"""
(function() {
    var panel = document.querySelector('.react-grid-item');
    var done = panel && panel.querySelector('[data-render-complete="true"]');
    var busy = document.querySelectorAll('[data-render-complete="false"], .euiLoadingChart, '
        + '.euiLoadingSpinner, .kbnLoadingIndicator').length > 0;
    return (done && !busy) ? 1 : 0;
})();
"""

# Bounding box of the dashboard's one panel, in CSS pixels.
_PANEL_RECT_JS = r"""
(function() {
    var el = document.querySelector('.react-grid-item')
          || document.querySelector('[data-test-subj="dashboardPanel"]');
    if (!el) { return ""; }
    var r = el.getBoundingClientRect();
    return JSON.stringify({x: r.left, y: r.top, w: r.width, h: r.height});
})();
"""

_IMPORT_JS = r"""
(function() {
    window.__hpTimelineImport = 0;
    var fd = new FormData();
    fd.append('file', new Blob([%(ndjson)s], {type: 'application/ndjson'}), 'timeline.ndjson');
    fetch(%(url)s, {method: 'POST', headers: {'kbn-xsrf': 'true'}, body: fd,
                    credentials: 'same-origin'})
        .then(function(r) { window.__hpTimelineImport = r.status; })
        .catch(function() { window.__hpTimelineImport = -1; });
})();
"""


class KibanaTimelineCapture(QObject):
    def __init__(self, base_url: str, autologin_js: str | None = None, parent=None):
        super().__init__(parent)
        self._base = base_url.rstrip("/")
        self._autologin_js = autologin_js
        self._profile = QWebEngineProfile("exploit_report_kibana", self)
        self._page = QWebEnginePage(self._profile, self)
        self._page.certificateError.connect(self._on_cert_error)
        self._view = QWebEngineView()
        self._view.setPage(self._page)
        self._view.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
        self._view.resize(CAPTURE_WIDTH, _VIEWPORT_HEIGHT)
        self._view.show()
        self._view.loadFinished.connect(self._on_load_finished)
        self._timer = QTimer(self)
        self._timer.setInterval(_POLL_MS)
        self._timer.timeout.connect(self._tick)

        self._imported = False
        self._phase = "idle"
        self._url = ""
        self._out = ""
        self._done = None
        self._started = 0.0
        self._phase_started = 0.0
        self._quiet = 0
        self._login_tried = False

    # ---- public ----

    def capture(self, start_epoch: float, end_epoch: float, out_path: str, done) -> None:
        """Grab the timeline for ``start_epoch`` .. ``end_epoch`` into
        ``out_path``, then call ``done(path or "")``."""
        self._url = kibana_timeline.timeline_url(self._base, start_epoch, end_epoch)
        self._out = out_path
        self._done = done
        self._started = time.monotonic()
        self._login_tried = False
        self._timer.start()
        if self._imported:
            self._load_target()
        else:
            # Any SIEM Analytics page: logs in (if needed) and gives the import a
            # same-origin session.
            self._set_phase("login")
            self._view.load(QUrl(self._base + "/app/home"))

    def close(self) -> None:
        self._timer.stop()
        self._view.stop()
        self._view.deleteLater()

    # ---- steps ----

    def _set_phase(self, phase: str) -> None:
        self._phase = phase
        self._phase_started = time.monotonic()
        self._quiet = 0

    def _load_target(self) -> None:
        self._set_phase("blank")
        # Via about:blank: two timelines differ only in the URL fragment, which
        # would otherwise be a same-document navigation without a reload.
        self._view.load(QUrl("about:blank"))

    def _finish(self, path: str) -> None:
        self._timer.stop()
        self._phase = "idle"
        done, self._done = self._done, None
        if done is not None:
            done(path)

    def _on_cert_error(self, error: QWebEngineCertificateError) -> None:
        # Kibana uses this repo's self-signed cert (see browser_widget.py).
        error.acceptCertificate()

    def _on_load_finished(self, ok: bool) -> None:
        if self._phase == "blank":
            self._set_phase("loading")
            self._view.load(QUrl(self._url))
            return
        if self._phase not in ("login", "loading") or not ok:
            return
        if self._view.url().path() == "/login":
            if self._autologin_js and not self._login_tried:
                self._login_tried = True
                self._page.runJavaScript(self._autologin_js)
            return
        if self._phase == "login":
            self._set_phase("import")
            self._page.runJavaScript(_IMPORT_JS % {
                "ndjson": json.dumps(kibana_timeline.saved_objects_ndjson()),
                "url": json.dumps(self._base + "/api/saved_objects/_import?overwrite=true"),
            })
            return
        self._set_phase("settling")

    def _tick(self) -> None:
        if self._phase == "idle":
            self._timer.stop()
            return
        if time.monotonic() - self._started > _TIMEOUT_S:
            self._finish("")
            return
        if self._phase == "import":
            self._page.runJavaScript("window.__hpTimelineImport || 0", self._on_import)
        elif self._phase == "settling":
            self._page.runJavaScript(_READY_JS, self._on_probe)

    def _on_import(self, status) -> None:
        if self._phase != "import" or not status:
            return
        if isinstance(status, (int, float)) and 200 <= status < 300:
            self._imported = True
            self._load_target()
        else:
            self._finish("")

    def _on_probe(self, result) -> None:
        if self._phase != "settling":
            return
        self._quiet = self._quiet + 1 if result == 1 else 0
        if self._quiet >= 2 and time.monotonic() - self._phase_started >= _MIN_SETTLE_S:
            self._set_phase("grab")
            self._page.runJavaScript(_PANEL_RECT_JS, self._on_rect)

    def _on_rect(self, result) -> None:
        if self._phase != "grab":
            return
        img = self._view.grab().toImage()
        if img.isNull():
            self._finish("")
            return
        try:
            r = json.loads(result) if result else None
        except ValueError:
            r = None
        if r and r.get("w", 0) > 50 and r.get("h", 0) > 50:
            scale = img.width() / max(1, self._view.width())
            pad = 4
            rect = QRect(int((r["x"] - pad) * scale), int((r["y"] - pad) * scale),
                         int((r["w"] + 2 * pad) * scale), int((r["h"] + 2 * pad) * scale))
            img = img.copy(rect.intersected(img.rect()))
        self._finish(self._out if img.save(self._out) else "")
