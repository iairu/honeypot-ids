"""Parses reverse_proxy log lines into structured threat-analyzer events,
for ui/page_exploits.py's colored score badge and diagram tab.

Regex-based against the actual ngx.log() message formats in
threat_analyzer.lua, router.lua, and nginx.conf's header_filter_by_lua
blocks -- if one of those message strings changes, the corresponding
pattern here needs updating to match (there's no shared source of truth,
same tradeoff as core/exploits.py's presets vs. init.lua's cve_patterns).

Recognized line shapes (roughly highest-value/most-specific first, since
parse_line() checks in this order and returns on the first match):
  - "[LOCATION / HEADER] route_decision='X' threat_score='N'" -- nginx.conf,
    fired on EVERY request exactly once, most reliable per-request outcome
    summary. Drives the score badge.
  - "[FINAL DECISION] (emoji) ROUTING TO (HONEYPOT|PRODUCTION) | Score: N
    [| Reason: ...]" -- nginx.conf, router.lua's own outcome record.
  - "[THREAT ANALYZER] (emoji) FINAL SCORE: N/M (verdict)" -- threat_analyzer.lua.
  - "[ROUTING] (emoji) <reason text> (HONEYPOT|PRODUCTION) ..." -- router.lua's
    per-stage routing decisions (Stage 3-10).
  - "[THREAT ANALYZER] ... Known threat IP detected: IP | Reason: X" --
    informational context for the "Bad IP reputation" signal that follows.
  - "[THREAT ANALYZER] (emoji) <label> (+N) [| detail]" -- individual
    scoring signals (URI patterns, headers, CVE match, automation, etc.).
Anything else returns None (not every log line is threat-analyzer-relevant
-- SESSION DEBUG, HEALTH, docker_logs source noise, etc. are deliberately
not shown in the diagram).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace

# Diagram/badge color palette -- reused across both.
COLOR_LOW = "#5cb85c"    # green: benign / production / small score delta
COLOR_MED = "#f0ad4e"    # orange: elevated / medium score delta
COLOR_HIGH = "#d9534f"   # red: honeypot / suspicious / large score delta
COLOR_INFO = "#5bc0de"   # blue: informational context, not a score itself


@dataclass(frozen=True)
class ThreatEvent:
    kind: str  # "outcome" | "final_score" | "routing" | "signal" | "info"
    label: str
    detail: str
    color: str
    score: int | None = None  # populated for "outcome"/"final_score" events
    # Original log timestamp (RFC3339, e.g. "2026-08-07T10:32:37.684747138Z"),
    # populated only when the tailing command was run with `docker compose
    # logs --timestamps` (ui/page_exploits.py's threat_log tail; NOT
    # ui/security_feed.py's, which doesn't need per-event timestamps for its
    # own purposes) -- None otherwise. See _DOCKER_TIMESTAMP_RE below.
    timestamp: str | None = None


# `docker compose logs --timestamps` prefixes EVERY line with
# "<service-name>  | <RFC3339-nano timestamp>Z " regardless of whether the
# underlying app prints its own timestamp -- confirmed live against this
# repo's own reverse_proxy container. Stripped off (and captured) before the
# rest of parse_line's matching, which all runs against the ORIGINAL nginx
# log message shape either way.
#
# The (?:\x1b\[[0-9;]*m)* right before the timestamp digits matters: every
# `docker compose logs` call in this app goes through Target.build(), which
# always adds --ansi always (see core/docker_ctl.py's _global_flags -- needed
# so colorized log output survives QProcess's non-TTY pipe). Confirmed live
# (piped through `cat -v`) that this wraps the "<service> | " prefix in a
# color escape and puts a SEPARATE reset escape (\x1b[0m) directly in front
# of the timestamp itself: "...reverse_proxy-1  | \x1b[0m2026-08-09T...".
# Without skipping that reset code here, the regex never matched at all --
# every single event's timestamp came back None, not just some -- which is
# why "Copy selected" on the Threat analyzer tab always showed "unknown
# time" instead of the real log timestamp.
_DOCKER_TIMESTAMP_RE = re.compile(
    r"^\S+\s*\|\s*(?:\x1b\[[0-9;]*m)*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s*"
)

_HEADER_SUMMARY_RE = re.compile(r"\[LOCATION / HEADER\] route_decision='(\w+)' threat_score='(-?\d+)'")
_FINAL_DECISION_RE = re.compile(
    r"\[FINAL DECISION\].*ROUTING TO (HONEYPOT|PRODUCTION)\s*\|\s*Score:\s*(-?\d+)(.*)$"
)
_FINAL_SCORE_RE = re.compile(r"\[THREAT ANALYZER\].*FINAL SCORE:\s*(-?\d+)/(\d+)\s*\(([^)]+)\)")
_ROUTING_RE = re.compile(r"\[ROUTING\]\s*(.+?)\s*(HONEYPOT|PRODUCTION)\b(.*)$")
_KNOWN_THREAT_RE = re.compile(r"\[THREAT ANALYZER\].*Known threat IP detected:\s*(\S+)\s*\|\s*Reason:\s*(.+)$")
_SIGNAL_RE = re.compile(r"\[THREAT ANALYZER\]\s*(?:[^\x00-\x7f]+\s*)?(.+?)\s*\(\+(\d+)\)(.*)$")

_EMOJI_PREFIX_RE = re.compile(r"^[^\x00-\x7f\s]+\s*")


def _strip_emoji(text: str) -> str:
    return _EMOJI_PREFIX_RE.sub("", text).strip()


def _strip_seps(text: str) -> str:
    return text.strip(" |->→")  # trailing "| ", "-", "->", or a stray arrow


def _signal_color(delta: int) -> str:
    if delta >= 30:
        return COLOR_HIGH
    if delta >= 10:
        return COLOR_MED
    return COLOR_LOW


def parse_line(line: str) -> ThreatEvent | None:
    line = line.strip()
    if not line:
        return None

    timestamp = None
    m_ts = _DOCKER_TIMESTAMP_RE.match(line)
    if m_ts:
        timestamp = m_ts.group(1)
        line = line[m_ts.end():]

    event = _parse_line_body(line)
    if event is None:
        return None
    return replace(event, timestamp=timestamp) if timestamp else event


def _parse_line_body(line: str) -> ThreatEvent | None:
    # nginx appends ", client: <ip>, server: ..., request: ...\" ..." to
    # EVERY log line (its own context, not part of the Lua message) --
    # strip it before matching so extracted "detail" text doesn't carry it.
    line = line.split(", client:")[0]

    m = _HEADER_SUMMARY_RE.search(line)
    if m:
        decision, score_str = m.group(1), m.group(2)
        try:
            score = int(score_str)
        except ValueError:
            score = 0
        color = COLOR_HIGH if decision == "honeypot" else COLOR_LOW
        return ThreatEvent("outcome", f"Routed to {decision.upper()}", f"Score: {score}", color, score)

    m = _FINAL_DECISION_RE.search(line)
    if m:
        target, score_str, rest = m.group(1), m.group(2), m.group(3)
        try:
            score = int(score_str)
        except ValueError:
            score = 0
        color = COLOR_HIGH if target == "HONEYPOT" else COLOR_LOW
        return ThreatEvent("outcome", f"Final decision: {target}", _strip_seps(rest) or f"Score: {score}", color, score)

    m = _FINAL_SCORE_RE.search(line)
    if m:
        score_str, threshold, verdict = m.group(1), m.group(2), m.group(3)
        try:
            score = int(score_str)
        except ValueError:
            score = 0
        verdict_lower = verdict.lower()
        if "suspicious" in verdict_lower:
            color = COLOR_HIGH
        elif "elevated" in verdict_lower:
            color = COLOR_MED
        else:
            color = COLOR_LOW
        return ThreatEvent("final_score", f"Final score: {score}/{threshold}", verdict, color, score)

    m = _ROUTING_RE.search(line)
    if m:
        label, target, rest = m.group(1), m.group(2), m.group(3)
        color = COLOR_HIGH if target == "HONEYPOT" else COLOR_LOW
        return ThreatEvent("routing", _strip_seps(_strip_emoji(label)), _strip_seps(rest), color)

    m = _KNOWN_THREAT_RE.search(line)
    if m:
        ip, reason = m.group(1), m.group(2)
        return ThreatEvent("info", f"Known threat IP: {ip}", reason.strip(), COLOR_INFO)

    m = _SIGNAL_RE.search(line)
    if m:
        label, delta_str, rest = m.group(1), m.group(2), m.group(3)
        delta = int(delta_str)
        clean_label = _strip_seps(_strip_emoji(label))
        return ThreatEvent("signal", f"{clean_label} (+{delta})", _strip_seps(rest), _signal_color(delta))

    return None


class LineBuffer:
    """Reassembles complete lines from arbitrary-sized text chunks (same
    problem ui/ansi.py solves for escape sequences) -- QProcess delivers
    output in whatever chunk boundaries the OS pipe gives it, which don't
    line up with log line boundaries."""

    def __init__(self) -> None:
        self._pending = ""

    def feed(self, chunk: str) -> list[str]:
        text = self._pending + chunk
        lines = text.split("\n")
        self._pending = lines.pop()  # last element: either "" or an incomplete line
        return lines
