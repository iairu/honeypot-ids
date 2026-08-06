"""Background polling for container status across all configured targets
(edge local, edge remote, siem local, siem remote). Runs in a QThread so
slow/unreachable SSH targets never freeze the UI.
"""
from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal


class StatusPoller(QThread):
    """Polls every `interval_ms`, forever, until stop() is called.

    `get_targets` is a callable (not a fixed list) so it can be called
    fresh at the start of each poll cycle -- targets change at runtime
    when the user edits remote settings.
    """
    results_ready = pyqtSignal(dict)

    def __init__(self, get_targets, interval_ms: int = 5000, parent=None):
        super().__init__(parent)
        self._get_targets = get_targets
        self._interval_ms = interval_ms
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        while not self._stop:
            results: dict[str, list[dict]] = {}
            for target in self._get_targets():
                if self._stop:
                    return
                results[target.key] = target.ps()
            if self._stop:
                return
            self.results_ready.emit(results)
            self.msleep(self._interval_ms)
