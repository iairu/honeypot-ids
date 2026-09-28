"""Background polling for container status across all configured targets
(edge local, edge remote, siem local, siem remote). Runs in a QThread so
slow/unreachable SSH targets never freeze the UI.
"""
from __future__ import annotations

import threading

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
        # Set to cut the current sleep short (poll_now()/stop()).
        self._wake = threading.Event()

    def stop(self) -> None:
        self._stop = True
        self._wake.set()

    def poll_now(self) -> None:
        """Run the next poll right away instead of after the rest of the
        interval. Safe to call from the GUI thread; a call that lands while
        a poll is already running just triggers one more straight after."""
        self._wake.set()

    def set_interval(self, interval_ms: int) -> None:
        """Takes effect on the next sleep -- read fresh every loop
        iteration, so no restart of the thread is needed."""
        self._interval_ms = interval_ms

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
            self._wake.wait(self._interval_ms / 1000)
            self._wake.clear()
