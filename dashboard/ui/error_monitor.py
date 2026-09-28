"""Tracks, per (target_key, service), how many log lines seen so far
contain an error word -- "error", or anything starting with "fail" or
"fault", case-insensitive (see core/log_error_match.py) -- fed entirely by the
Services page's always-running combined log tail for each target (see
page_services.py's TargetPanel), so it keeps working regardless of which
page is currently visible and without starting any extra `docker compose
logs` processes of its own.
"""
from __future__ import annotations

from PyQt6.QtCore import QObject, pyqtSignal

from core.line_buffer import LineBuffer
from core.log_error_match import _ANSI_RE, _PREFIX_RE, _message_is_error


class ErrorLogMonitor(QObject):
    counts_changed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._counts: dict[tuple[str, str], int] = {}
        self._buffers: dict[str, LineBuffer] = {}

    def count_for(self, target_key: str, service: str) -> int:
        return self._counts.get((target_key, service), 0)

    def reset(self, target_key: str) -> None:
        """Clears every count for one target. Called whenever a FRESH
        `docker compose logs -f` tail starts for that target (initial
        auto-tail, or resuming after Start/Restart/Stop/Purge) -- each such
        invocation replays its own `--tail=50` scrollback, so without this
        the same historical error lines would get re-counted every time the
        tail restarts instead of the counter reflecting "since this tail
        last started"."""
        self._buffers.pop(target_key, None)
        changed = False
        for key in [k for k in self._counts if k[0] == target_key]:
            del self._counts[key]
            changed = True
        if changed:
            self.counts_changed.emit()

    def process_chunk(self, target_key: str, chunk: str) -> None:
        lines = self._buffers.setdefault(target_key, LineBuffer()).feed(chunk)

        changed = False
        for line in lines:
            plain = _ANSI_RE.sub("", line)
            m = _PREFIX_RE.match(plain)
            if not m:
                continue
            if _message_is_error(m.group("message")):
                key = (target_key, m.group("service"))
                self._counts[key] = self._counts.get(key, 0) + 1
                changed = True
        if changed:
            self.counts_changed.emit()
