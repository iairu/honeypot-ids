"""What each honeypot pool's own containers saw and changed during a Pool test
run: the requests that reached its eshop (from the Apache access log, told
apart by each test window's User-Agent tag), files written inside that eshop,
and how far its database's statement counters moved.

Different windows run different exploits, so each pool's evidence should be its
owner's exploit and nobody else's -- that is what the Pool test report shows.
The parsers are pure (unit tested); the collectors shell out through the
project's compose Target, so they work for a remote edge host too.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from core.docker_ctl import Target
from core.proc import run_checked

# Counters whose growth means "this database was used".
DB_COUNTERS = ("Questions", "Com_select", "Com_insert", "Com_update", "Com_delete")

# Window tag the Pool test page puts in each frame's User-Agent ("PoolTest/A").
_WINDOW_RE = re.compile(r"PoolTest/([A-Z])")
_LOG_RE = re.compile(
    r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')
_ASSET_RE = re.compile(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(\?|$)", re.I)

# Paths written by Apache/WordPress on every run; never worth reporting.
_FILE_NOISE = ("/tmp/", "/proc/", "/sys/", "/run/", "/dev/")


class PoolEvidenceError(Exception):
    pass


@dataclass
class Hit:
    window: str          # "A", "B", ...
    method: str
    path: str
    status: int


@dataclass
class ContainerEvidence:
    pool: int
    hits: list[Hit] = field(default_factory=list)
    files_changed: list[str] = field(default_factory=list)
    db_delta: dict[str, int] | None = None   # None: no baseline (pool built mid-run)
    error: str = ""

    def windows(self) -> list[str]:
        return sorted({h.window for h in self.hits})

    def notable(self, limit: int = 8) -> list[Hit]:
        """Distinct non-asset requests, in the order they arrived."""
        seen, out = set(), []
        for h in self.hits:
            key = (h.window, h.method, h.path)
            if key in seen or _ASSET_RE.search(h.path):
                continue
            seen.add(key)
            out.append(h)
        return out[:limit]


def parse_status(text: str) -> dict[str, int]:
    """`SHOW GLOBAL STATUS` rows ("name<TAB>value") -> {name: int}."""
    out = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].strip().isdigit():
            out[parts[0].strip()] = int(parts[1])
    return out


def parse_access_log(text: str) -> list[Hit]:
    """Requests in an Apache combined log that came from a Pool test window."""
    hits = []
    for line in text.splitlines():
        m = _LOG_RE.match(line.strip())
        if not m:
            continue
        w = _WINDOW_RE.search(m.group(5))
        if w:
            hits.append(Hit(w.group(1), m.group(2), m.group(3), int(m.group(4))))
    return hits


def filter_files(paths: list[str]) -> list[str]:
    return [p for p in (x.strip() for x in paths) if p and not p.startswith(_FILE_NOISE)]


def db_delta(before: dict[str, int] | None, after: dict[str, int]) -> dict[str, int] | None:
    if before is None:
        return None
    return {k: after.get(k, 0) - before.get(k, 0) for k in DB_COUNTERS}


# ---- collectors (docker / compose) ----

def _run_container(target: Target, service: str, compose_args: tuple[str, ...],
                   docker_cmd: str, timeout: float, what: str) -> str:
    """Run against a pool container: through compose for the pools declared in
    the compose file, else straight through docker. Pools pool_manager built at
    runtime are plain containers named like the service (honeypot_eshop_4) and
    unknown to compose ("service ... is not running")."""
    argv, cwd = target.build(*compose_args)
    try:
        return run_checked(argv, error=PoolEvidenceError, cwd=cwd, timeout=timeout,
                           what=what).stdout
    except PoolEvidenceError as compose_error:
        argv, cwd = target.build_shell(docker_cmd)
        try:
            return run_checked(argv, error=PoolEvidenceError, cwd=cwd, timeout=timeout,
                               what=what).stdout
        except PoolEvidenceError:
            raise compose_error from None


def _exec(target: Target, service: str, command: str, timeout: float = 30.0) -> str:
    return _run_container(
        target, service, ("exec", "-T", service, "sh", "-c", command),
        f"docker exec {shlex.quote(service)} sh -c {shlex.quote(command)}",
        timeout, f"docker exec {service}")


def _logs(target: Target, service: str, since: str, timeout: float = 30.0) -> str:
    """The container's log since `since`. `docker compose logs` does not fail
    for a service it does not know -- it prints nothing and exits 0 -- so an
    empty answer is retried through plain docker, which knows the runtime
    pools (and fails for compose-named ones, keeping the empty answer)."""
    out = _run_container(
        target, service, ("logs", "--no-log-prefix", "--since", since, service),
        f"docker logs --since {shlex.quote(since)} {shlex.quote(service)} 2>&1",
        timeout, "docker logs")
    if out.strip():
        return out
    argv, cwd = target.build_shell(
        f"docker logs --since {shlex.quote(since)} {shlex.quote(service)} 2>&1")
    try:
        return run_checked(argv, error=PoolEvidenceError, cwd=cwd, timeout=timeout,
                           what="docker logs").stdout
    except PoolEvidenceError:
        return out


_STATUS_CMD = ("mysql -uroot -p\"$MYSQL_ROOT_PASSWORD\" -N -e \"SHOW GLOBAL STATUS WHERE "
               "Variable_name IN (" + ",".join(f"'{c}'" for c in DB_COUNTERS) + ")\" 2>/dev/null")


def db_status(target: Target, pool: int) -> dict[str, int] | None:
    try:
        return parse_status(_exec(target, f"honeypot_database_{pool}", _STATUS_CMD))
    except PoolEvidenceError:
        return None


_SINCE_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")


def take_baseline(target: Target, pools: list[int]) -> dict:
    """Start time (read from a pool's own container, so its clock is the one
    the logs and file times use) and each existing pool's DB counters."""
    since = ""
    for pool in pools:
        try:
            got = _exec(target, f"honeypot_eshop_{pool}", "date -u +%Y-%m-%dT%H:%M:%SZ").strip()
            if _SINCE_RE.match(got):   # interpolated into a shell command below
                since = got
                break
        except PoolEvidenceError:
            continue
    return {"since": since, "db": {p: db_status(target, p) for p in pools}, "pool_since": {}}


def extend_baseline(target: Target, baseline: dict, pools: list[int]) -> None:
    """Baseline for pools that came up during the run (built by pool_manager
    for windows that attack later): their DB counters and start time, taken
    before any test window reaches them, so their evidence covers the
    windows' traffic only and not the pool's own build."""
    tried = baseline.setdefault("tried", set())
    for pool in pools:
        if baseline.setdefault("db", {}).get(pool) is not None or pool in tried:
            continue
        tried.add(pool)
        try:
            got = _exec(target, f"honeypot_eshop_{pool}", "date -u +%Y-%m-%dT%H:%M:%SZ").strip()
        except PoolEvidenceError:
            continue
        if _SINCE_RE.match(got):
            baseline["db"][pool] = db_status(target, pool)
            baseline.setdefault("pool_since", {})[pool] = got
            if not baseline.get("since"):
                baseline["since"] = got


def collect(target: Target, pools: list[int], baseline: dict) -> list[ContainerEvidence]:
    out = []
    for pool in pools:
        since = baseline.get("pool_since", {}).get(pool) or baseline.get("since", "")
        ev = ContainerEvidence(pool)
        try:
            if not since:
                ev.error = "Could not read the start time from the pool containers."
            else:
                log = _logs(target, f"honeypot_eshop_{pool}", since)
                ev.hits = parse_access_log(log)
                files = _exec(target, f"honeypot_eshop_{pool}",
                              "find / -xdev \\( -path /proc -o -path /sys -o -path /run -o -path /dev \\) "
                              f"-prune -o -type f -newermt '{since}' -print 2>/dev/null | head -60")
                ev.files_changed = filter_files(files.splitlines())
            after = db_status(target, pool)
            ev.db_delta = db_delta(baseline.get("db", {}).get(pool), after) if after else None
        except PoolEvidenceError as e:
            ev.error = str(e)
        out.append(ev)
    return out


def cross_traffic(evidence: list[ContainerEvidence], owners: dict[int, str]) -> list[str]:
    """Findings for pools that served a window other than their owner."""
    out = []
    for ev in evidence:
        owner = owners.get(ev.pool)
        others = [w for w in ev.windows() if owner and w != owner]
        if others:
            out.append(f"Pool {ev.pool} (owned by window {owner}) also served window(s) "
                       f"{', '.join(others)}.")
    return out
