"""Parses honeypot_content_sync's stdout log lines into a small activity
summary -- backs ui/page_health.py's per-pool status panel.

honeypot_content_sync (see ids/scripts/replicate_content_to_honeypot.sh)
has no Docker healthcheck and writes no host-readable state file (its
$WORKDIR is an ephemeral in-container mktemp, cleaned up on exit) -- the
container's own State/Health only ever say "the loop process is alive",
never "the last sync cycle actually succeeded". The only place that
signal exists at all is stdout, one line per event, e.g.:

    [content-sync 2026-08-09T02:00:00Z] honeypot content sync starting -- interval 300s
    [content-sync 2026-08-09T02:00:01Z] built sync script covering 42 production content item(s)
    [content-sync 2026-08-09T02:00:01Z] pool 1 (honeypot_database_1): replication starting
    [content-sync 2026-08-09T02:00:02Z] pool 1 (honeypot_database_1): replication complete
    [content-sync 2026-08-09T02:00:04Z] pool 2 (honeypot_database_2): replication FAILED -- pool DB left as-is, will retry next cycle

so this module re-parses that text (fed in from the same `docker compose
logs -f honeypot_content_sync` tail the Health page already runs for
every node's log panel -- no extra docker-exec round trip needed) rather
than adding any new backend signal.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_LINE_RE = re.compile(r"\[content-sync (?P<ts>\S+)\]\s*(?P<msg>.*)")
_POOL_RE = re.compile(r"^pool (?P<num>\d+) \([\w.-]+\): replication (?P<status>starting|complete|FAILED)")


@dataclass(frozen=True)
class PoolSyncStatus:
    status: str  # "starting" | "complete" | "failed"
    timestamp: str


@dataclass(frozen=True)
class ContentSyncActivity:
    per_pool: dict[int, PoolSyncStatus] = field(default_factory=dict)
    last_message: str | None = None
    last_timestamp: str | None = None


def parse_content_sync_log(text: str) -> ContentSyncActivity:
    """Re-parses the FULL accumulated log text each call (cheap at the
    buffer sizes callers keep -- see page_health.py) rather than trying
    to track partial lines across chunk boundaries itself; always
    correct regardless of how output happened to be chunked."""
    per_pool: dict[int, PoolSyncStatus] = {}
    last_message: str | None = None
    last_timestamp: str | None = None

    for m in _LINE_RE.finditer(text):
        ts, msg = m.group("ts"), m.group("msg").strip()
        if not msg:
            continue
        last_message, last_timestamp = msg, ts

        pool_m = _POOL_RE.match(msg)
        if pool_m:
            num = int(pool_m.group("num"))
            status = pool_m.group("status").lower()
            per_pool[num] = PoolSyncStatus(status=status, timestamp=ts)

    return ContentSyncActivity(per_pool=per_pool, last_message=last_message, last_timestamp=last_timestamp)
