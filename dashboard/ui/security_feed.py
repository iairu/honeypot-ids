"""App-lifetime background tail of reverse_proxy's own logs, independent of
whether the Exploits page is even open -- parsed via core/threat_log_parser
(the same parser page_exploits.py's score badge/diagram tab use), filtered
down to NOTABLE events (honeypot diversions, CVE/high-severity signals --
anything the parser already tags COLOR_HIGH) plus dependency-check
failures (see add_dependency_event()), and persisted to
AppState.security_events (capped, survives app restarts).

Powers the Overview page's "current score" and "recent security events"
list. Owned by MainWindow, started once at app startup and restarted
whenever remote settings change -- mirrors ui/status_poller.StatusPoller
already running continuously for the app's whole lifetime regardless of
which page is visible, just log-tail-based instead of poll-based.

Reuses ui/process_runner.LogPanel purely for its QProcess plumbing (spawn,
ANSI-safe chunk buffering via line_received, stop/restart) -- this instance
is never shown or added to any layout, just driven headlessly.
"""
from __future__ import annotations

import time

from PyQt6.QtCore import QObject, pyqtSignal

from core.docker_ctl import Target
from core.state import AppState
from core.threat_log_parser import COLOR_HIGH, LineBuffer, ThreatEvent, parse_line
from ui.process_runner import LogPanel

MAX_EVENTS = 200


def _event_to_dict(event: ThreatEvent, timestamp: int) -> dict:
    return {
        "timestamp": timestamp,
        "kind": event.kind,
        "label": event.label,
        "detail": event.detail,
        "color": event.color,
        "score": event.score,
    }


def event_from_dict(d: dict) -> tuple[ThreatEvent, int]:
    event = ThreatEvent(
        kind=d.get("kind", "info"),
        label=d.get("label", ""),
        detail=d.get("detail", ""),
        color=d.get("color", COLOR_HIGH),
        score=d.get("score"),
    )
    return event, d.get("timestamp", 0)


class SecurityEventFeed(QObject):
    # Emitted for every notable event as it's recorded: (ThreatEvent, unix timestamp).
    event_added = pyqtSignal(object, int)
    # Emitted whenever a fresh per-request outcome score is seen (every
    # request, not just notable ones) -- for a live "current score" display.
    score_changed = pyqtSignal(object)  # int score, or None if unavailable

    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self._line_buffer = LineBuffer()
        self._runner = LogPanel(show_stop_button=False)  # never shown/laid out
        self._runner.line_received.connect(self._on_output)
        self.latest_score: int | None = None

    def start(self, target: Target) -> None:
        """(Re)points the tail at `target` -- LogPanel.run() already kills
        any previous process first, so this is safe to call again whenever
        remote settings change."""
        self._line_buffer = LineBuffer()
        # --tail=0: only new lines from here on. Re-parsing old backlog on
        # every app start/restart would re-emit (and re-persist duplicates
        # of) events already recorded in a previous session.
        argv, cwd = target.build("logs", "--tail=0", "-f", "reverse_proxy")
        self._runner.run(argv, cwd)

    def stop(self) -> None:
        self._runner.stop()

    def recent_events(self) -> list[tuple[ThreatEvent, int]]:
        """Persisted history from previous sessions plus this one, oldest
        first -- what a freshly-opened Overview page should seed itself
        with before any live event_added signal has fired yet."""
        return [event_from_dict(d) for d in self.state.security_events]

    def _on_output(self, chunk: str) -> None:
        for line in self._line_buffer.feed(chunk):
            event = parse_line(line)
            if event is None:
                continue
            if event.kind == "outcome" and event.score is not None:
                self.latest_score = event.score
                self.score_changed.emit(event.score)
            if event.color != COLOR_HIGH:
                continue
            self._record(event)

    def add_dependency_event(self, detail: str) -> None:
        """Hook for ui/dependency_banner.py: a required package going
        missing is 'notable' the same way a honeypot diversion is, even
        though it has nothing to do with reverse_proxy's own logs."""
        self._record(ThreatEvent(kind="info", label="Missing required dependency", detail=detail, color=COLOR_HIGH))

    def _record(self, event: ThreatEvent) -> None:
        timestamp = int(time.time())
        self.state.security_events.append(_event_to_dict(event, timestamp))
        del self.state.security_events[:-MAX_EVENTS]
        self.state.save()
        self.event_added.emit(event, timestamp)
