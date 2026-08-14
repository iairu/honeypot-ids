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

# docker compose logs' multi-service line prefix. Usually
# "<service>-<replica-number>  | message" (e.g. "honeypot_eshop_1-1  | ...",
# "vector_outbound-1  | ...") -- compose service names are underscore-separated, so
# that trailing "-N" is unambiguous to strip back off. BUT: a service with
# an explicit `container_name:` override (siem/docker/docker-compose.yml's
# es01/kibana/vector_inbound) drops the "-N" entirely, e.g. "kibana  | ...".
# Confirmed live this second form is real, not hypothetical: those three
# SIEM services' error lines (including a genuine ERROR from vector_inbound's own
# elasticsearch sink) were silently never counted before the "-\d+" here
# became optional, since the old, mandatory version of it never matched
# their prefix at all. The service-name character class itself (no
# hyphen in it) is what keeps this unambiguous either way -- "-N" can
# only ever be the optional replica suffix, never part of the name.
_PREFIX_RE = re.compile(r"^(?P<service>[A-Za-z0-9_.]+)(?:-\d+)?\s*\|\s?(?P<message>.*)$")

# NOT a plain \b word-boundary match -- confirmed live that Vector's own
# routine startup log line ("component_id=nginx_error_in ... include=
# [\"/var/log/nginx/error.log\"]") still flags on this, since \b only
# excludes adjacent \w characters (letters/digits/underscore): that rules
# out "nginx_error_in" (joined by "_") but NOT "error.log" (joined by "."),
# so the same line still matches via its second "error". Also excluding
# "." and "/" (and "-") from what counts as a boundary rules out both --
# file paths/extensions/identifiers built from any of these don't count,
# while a genuine "[error]"/"ERROR"/"Error:" token (surrounded by
# whitespace/punctuation outside this set) still does.
_ERROR_RE = re.compile(r"(?<![\w./-])error(?![\w./-])", re.IGNORECASE)

# Kibana's own structured log format: "[timestamp][LEVEL ][context] message"
# (e.g. "[2026-08-13T16:49:29.727+00:00][INFO ][plugins.notifications] Email
# Service Error: Email connector not specified."). When a line matches this
# AND declares a quiet level, that declared severity is trusted over a raw
# "error" keyword scan of the text -- same reasoning as nginx's own
# [error]/[info] severity-tag fix elsewhere in this app. Confirmed live this
# is real, not hypothetical: Kibana's notifications plugin logs exactly that
# INFO line, unconditionally, at startup whenever no email connector is
# configured -- which is the correct, expected state for this deployment (no
# SMTP server exists anywhere in this system), not a fault. There's no
# config knob to stop Kibana logging it at all (confirmed by reading
# @kbn/notifications-plugin's source in the running container -- the
# connectors.default.email config has no "disable this check" option), so
# trusting the level tag it already carries is the only real fix available.
# WARN/ERROR/FATAL (or any line not matching Kibana's format at all -- every
# other service's logs) still fall through to the plain keyword scan.
_KIBANA_LEVEL_RE = re.compile(r"^\[[^\]]+\]\[\s*([A-Z]+)\s*\]\[")
_KIBANA_QUIET_LEVELS = {"TRACE", "DEBUG", "INFO"}


def _message_is_error(message: str) -> bool:
    kibana_level = _KIBANA_LEVEL_RE.match(message)
    if kibana_level and kibana_level.group(1) in _KIBANA_QUIET_LEVELS:
        return False
    return bool(_ERROR_RE.search(message))


def is_error_log_line(raw_line: str) -> bool:
    """True if `raw_line` (a single line as delivered by `docker compose
    logs` -- ANSI codes and the "<service>-N | " prefix intact, if
    present) contains the word "error" in its message portion -- the
    exact same test process_chunk() uses per-line to increment a badge
    count, exposed for reuse by anything that wants to filter down to
    just the lines that would increment it (e.g. the Health page's "view
    this service's error lines only" action, clicking a node's badge)."""
    plain = _ANSI_RE.sub("", raw_line)
    m = _PREFIX_RE.match(plain)
    message = m.group("message") if m else plain
    return _message_is_error(message)


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
            if _message_is_error(m.group("message")):
                key = (target_key, m.group("service"))
                self._counts[key] = self._counts.get(key, 0) + 1
                changed = True
        if changed:
            self.counts_changed.emit()
