"""Tracks, per (target_key, service), how many log lines seen so far
contain the word "error" (case-insensitive) -- fed entirely by the
Services page's always-running combined log tail for each target (see
page_services.py's TargetPanel), so it keeps working regardless of which
page is currently visible and without starting any extra `docker compose
logs` processes of its own.
"""
from __future__ import annotations

import re

from PyQt6.QtCore import QObject, pyqtSignal

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# docker compose logs' default multi-service line prefix, e.g.
# "honeypot_eshop_1-1  | actual message" or "vector-1  | ...". Compose
# service names are underscore-separated, so the "-<replica-number>"
# suffix docker compose appends is unambiguous to strip back off.
_PREFIX_RE = re.compile(r"^(?P<service>[A-Za-z0-9_.]+)-\d+\s*\|\s?(?P<message>.*)$")


class ErrorLogMonitor(QObject):
    counts_changed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._counts: dict[tuple[str, str], int] = {}
        # Holds each target's trailing incomplete line across process_chunk()
        # calls -- QProcess delivers output in arbitrary-sized chunks that
        # don't line up with line boundaries.
        self._buffers: dict[str, str] = {}

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
        text = self._buffers.pop(target_key, "") + chunk
        lines = text.split("\n")
        # The last element is either "" (chunk ended exactly on a newline)
        # or an incomplete line -- either way, hold it for the next chunk
        # rather than matching a truncated line now.
        self._buffers[target_key] = lines.pop()

        changed = False
        for line in lines:
            plain = _ANSI_RE.sub("", line)
            m = _PREFIX_RE.match(plain)
            if not m:
                continue
            if "error" in m.group("message").lower():
                key = (target_key, m.group("service"))
                self._counts[key] = self._counts.get(key, 0) + 1
                changed = True
        if changed:
            self.counts_changed.emit()
