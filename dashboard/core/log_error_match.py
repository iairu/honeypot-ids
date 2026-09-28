"""Decides which `docker compose logs` lines count as errors -- the test
behind the Health page's red "!N" badges (ui/error_monitor.py) and the
badge-click "error lines only" log view. Qt-free so it can be unit-tested
without the app's PyQt6 venv.

A line counts when its message contains the word "error", or a word starting
with "fail" or "fault" ("failed", "Failure", "faults", "faulty", ...), in any
case.
"""
from __future__ import annotations

import re

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
#
# "fail"/"fault" take any word ending ("failed", "failure", "faulty") but keep
# the same boundaries, so "default", "fail2ban", "on_failure" or "/fail.log"
# style identifiers and paths still don't count.
_ERROR_RE = re.compile(
    r"(?<![\w./-])(?:error|fail[a-z]*|fault[a-z]*)(?![\w./-])",
    re.IGNORECASE,
)

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
    present) contains an error word (see the module docstring) in its
    message portion -- the
    exact same test process_chunk() uses per-line to increment a badge
    count, exposed for reuse by anything that wants to filter down to
    just the lines that would increment it (e.g. the Health page's "view
    this service's error lines only" action, clicking a node's badge)."""
    plain = _ANSI_RE.sub("", raw_line)
    m = _PREFIX_RE.match(plain)
    message = m.group("message") if m else plain
    return _message_is_error(message)
