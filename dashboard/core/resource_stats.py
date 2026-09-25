"""Per-container resource collection for the Resources page.

Three cheap shell one-liners run through the same Target plumbing every other
docker-facing feature uses (local `sh -c`, or SSH for a remote target):

  * live stats  -- `docker stats --no-stream` scoped to the project's own
    containers (CPU%, memory, net/block I/O, PIDs). Polled frequently.
  * container list -- `docker compose ps` for the Name -> Service/State map
    (docker stats only knows the container name, not the compose service).
  * log sizes -- the on-disk size of each container's json-file log. Those
    live under /var/lib/docker/containers, which is root-only, so instead of
    needing host sudo they're `du`'d from inside a throwaway alpine container
    that mounts that directory read-only (the docker daemon is root). Polled
    less often since log files grow slowly and this spawns a container.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass

from core.docker_ctl import Target


@dataclass
class ContainerResource:
    name: str          # full container name, e.g. honeypot-ids-system-v1-production_eshop-1
    service: str       # compose service, e.g. production_eshop
    state: str         # running | exited | ...
    cid: str = ""      # short container id
    cpu_percent: float = 0.0
    mem_used_bytes: int = 0
    mem_limit_bytes: int = 0
    mem_percent: float = 0.0
    net_io: str = ""
    block_io: str = ""
    pids: int = 0
    log_bytes: int = 0

    @property
    def running(self) -> bool:
        return self.state == "running"


# docker stats mixes IEC (MiB/GiB, memory) and SI (kB/MB, net/block) units;
# handle both, case-insensitively.
_SIZE_RE = re.compile(r"([\d.]+)\s*([KMGTP]?I?B)", re.IGNORECASE)
_MULT = {
    "B": 1,
    "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12, "PB": 10**15,
    "KIB": 1024, "MIB": 1024**2, "GIB": 1024**3, "TIB": 1024**4, "PIB": 1024**5,
}


def _to_bytes(text: str) -> int:
    m = _SIZE_RE.search(text or "")
    if not m:
        return 0
    return int(float(m.group(1)) * _MULT.get(m.group(2).upper(), 1))


def _percent(text: str) -> float:
    try:
        return float((text or "").strip().rstrip("%"))
    except ValueError:
        return 0.0


def _run(target: Target, command: str, timeout: float) -> str:
    """Run a shell one-liner in the target's compose dir (or over SSH), return
    stdout ('' on any failure -- the caller degrades gracefully)."""
    argv, cwd = target.build_shell(command)
    try:
        result = subprocess.run(
            argv, cwd=cwd, capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def collect_live(target: Target, timeout: float = 12.0) -> list[ContainerResource]:
    """Live per-container stats + service/state, WITHOUT log sizes (those are
    fetched separately, less often). Returns [] on failure."""
    # Name -> (service, state, short id) from compose ps (includes stopped).
    listing = target.ps(timeout=timeout)
    meta: dict[str, dict] = {}
    for c in listing:
        name = c.get("Name")
        if name:
            meta[name] = c

    # Live stats for the project's running containers, scoped by their ids so
    # `docker stats` never reports unrelated containers on the host.
    stats_out = _run(
        target,
        "ids=$(docker compose --profile '*' ps -q 2>/dev/null); "
        "[ -n \"$ids\" ] && docker stats --no-stream --no-trunc "
        "--format '{{json .}}' $ids || true",
        timeout=timeout,
    )
    stats_by_name: dict[str, dict] = {}
    for line in stats_out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            s = json.loads(line)
        except json.JSONDecodeError:
            continue
        if s.get("Name"):
            stats_by_name[s["Name"]] = s

    results: list[ContainerResource] = []
    # Union of everything ps knows about (so stopped containers still appear).
    for name in sorted(meta) or sorted(stats_by_name):
        c = meta.get(name, {})
        s = stats_by_name.get(name)
        res = ContainerResource(
            name=name,
            service=c.get("Service", name),
            state=(c.get("State") or ("running" if s else "unknown")),
            cid=(c.get("ID") or (s.get("ID", "")[:12] if s else "")),
        )
        if s:
            res.cpu_percent = _percent(s.get("CPUPerc", ""))
            mem = s.get("MemUsage", "")
            used, _, limit = mem.partition("/")
            res.mem_used_bytes = _to_bytes(used)
            res.mem_limit_bytes = _to_bytes(limit)
            res.mem_percent = _percent(s.get("MemPerc", ""))
            res.net_io = (s.get("NetIO", "") or "").strip()
            res.block_io = (s.get("BlockIO", "") or "").strip()
            try:
                res.pids = int(s.get("PIDs", "0") or 0)
            except ValueError:
                res.pids = 0
            # Full id from stats (ps only gives a short id) -- used to attach
            # the log size below.
            if s.get("ID"):
                res.cid = s["ID"][:12]
        results.append(res)
    return results


def collect_log_sizes(target: Target, timeout: float = 20.0) -> dict[str, int]:
    """{full_container_id: json_log_bytes} for every container's docker log, via
    a throwaway alpine container that mounts the (root-only) containers dir
    read-only. {} if that path/daemon layout isn't available (e.g. Docker
    Desktop VMs) -- the Resources page then just shows log size as n/a."""
    out = _run(
        target,
        "docker run --rm -v /var/lib/docker/containers:/c:ro alpine "
        "sh -c 'du -sb /c/*/*-json.log 2>/dev/null' 2>/dev/null || true",
        timeout=timeout,
    )
    sizes: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        size_str, path = parts
        m = re.search(r"/c/([0-9a-f]{12,64})/", path)
        if not m:
            continue
        try:
            sizes[m.group(1)] = int(size_str.strip())
        except ValueError:
            continue
    return sizes


def merge_log_sizes(resources: list[ContainerResource], log_sizes: dict[str, int]) -> None:
    """Attach each container's log size (matched by short-id prefix, since the
    compose/stats ids are truncated while the log dir keys are full ids)."""
    if not log_sizes:
        return
    for res in resources:
        cid = res.cid
        if not cid:
            continue
        if cid in log_sizes:
            res.log_bytes = log_sizes[cid]
            continue
        for full_id, size in log_sizes.items():
            if full_id.startswith(cid):
                res.log_bytes = size
                break


def human_bytes(n: int) -> str:
    if n <= 0:
        return "0 B"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TiB"
