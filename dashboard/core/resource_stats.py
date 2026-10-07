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
import os
import re
import shlex
import subprocess
import sys
import time
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


# Honeypot pool containers: compose-declared ("<project>-honeypot_eshop_2-1",
# "<project>-honeypot_database-1" = pool 1 of the database layer) and the ones
# pool_manager creates ("honeypot_eshop_5"), which compose ps never lists.
_POOL_CONTAINER_RE = re.compile(r"(?:^|-)honeypot_(eshop|database)(?:_(\d+))?(?:-\d+)?$")


def pool_container(name: str) -> tuple[str, int] | None:
    """("eshop" | "database", pool number) for a honeypot pool container name."""
    m = _POOL_CONTAINER_RE.search(name)
    return (m.group(1), int(m.group(2) or 1)) if m else None


@dataclass
class PoolUsage:
    """What all honeypot pool containers use at one moment."""
    containers: int = 0
    pools: int = 0
    mem_bytes: int = 0
    cpu_percent: float = 0.0     # sum over containers (100 = one CPU busy)
    per_pool_mem: dict = None    # pool -> bytes


def parse_pool_usage(stats_lines: str) -> PoolUsage:
    """PoolUsage from `docker stats --format '{{json .}}'` lines."""
    out = PoolUsage(per_pool_mem={})
    for line in stats_lines.splitlines():
        try:
            st = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = pool_container(st.get("Name", ""))
        if kind is None:
            continue
        mem = _to_bytes((st.get("MemUsage", "") or "").partition("/")[0])
        out.containers += 1
        out.mem_bytes += mem
        out.cpu_percent += _percent(st.get("CPUPerc", ""))
        out.per_pool_mem[kind[1]] = out.per_pool_mem.get(kind[1], 0) + mem
    out.pools = len(out.per_pool_mem)
    return out


def collect_pool_usage(target: Target, timeout: float = 20.0) -> PoolUsage:
    """Memory/CPU of every running honeypot pool container, runtime ones included."""
    text = _run(
        target,
        "ids=$(docker ps -q --filter name=honeypot_eshop --filter name=honeypot_database); "
        "[ -n \"$ids\" ] && docker stats --no-stream --format '{{json .}}' $ids || true",
        timeout=timeout)
    return parse_pool_usage(text)


# Sentinel from FastSampler._resolve(): the PID docker reported is not that
# container on this host.
_FOREIGN = object()


def cgroup_matches_container(proc_cgroup: str, full_id: str) -> bool:
    """True if a /proc/<pid>/cgroup listing places the process in the cgroup
    of container `full_id` (its full 64-hex id appears in a cgroup path)."""
    full_id = (full_id or "").strip().lower()
    if len(full_id) < 12:
        return False
    for line in proc_cgroup.splitlines():
        path = line.split(":", 2)[-1].lower()
        if full_id in path:
            return True
    return False


class FastSampler:
    """Sub-second per-container CPU% / memory, read straight from the cgroup
    filesystem instead of `docker stats` (which blocks ~1s per call to compute
    CPU% over its own interval).

    LOCAL host only: it reads /proc and /sys/fs/cgroup directly. For a remote
    target, or when the cgroup layout can't be resolved, ``available`` stays
    False and callers fall back to collect_live(). Container -> cgroup mapping
    is resolved ONCE at construction (a couple of docker calls); each sample()
    is then just a handful of tiny file reads (well under a millisecond each),
    so it can be polled several times a second.

    refresh() picks up containers that started (or were recreated) after
    construction -- a "Start with PDF graph export" from a stopped stack has
    nothing running yet when the sampler is built."""

    def __init__(self, target: Target):
        self.available = False
        # Set when the docker daemon's container PIDs turn out not to belong
        # to this host (see _resolve()); the sampler then stays unavailable for
        # good and callers use `docker stats` instead.
        self.foreign = False
        self._target = target
        self._paths: dict[str, dict] = {}   # service -> {mode, cpu, mem}
        self._cid: dict[str, str] = {}       # service -> short container id
        self._prev: dict[str, tuple[int, float]] = {}  # service -> (cpu_ns, wall)
        self._v2 = os.path.exists("/sys/fs/cgroup/cgroup.controllers")
        if target.is_remote:
            return
        try:
            listing = target.ps(timeout=10)
        except Exception:  # noqa: BLE001
            return
        self.refresh(listing)

    def refresh(self, listing: list[dict]) -> None:
        """Resolve cgroup paths for running containers in a `ps` listing that
        aren't being sampled yet, or whose container id changed (recreated).
        One `docker inspect` for just those; a no-op when nothing is new."""
        if self._target.is_remote or self.foreign:
            return
        running = {}
        for c in listing:
            cid = c.get("ID") or ""
            svc = c.get("Service") or c.get("Name") or ""
            if not (cid and svc and c.get("State") == "running"):
                continue
            known = self._cid.get(svc, "")
            if known and (known.startswith(cid[:12]) or cid.startswith(known)):
                continue
            running[cid] = svc
        if not running:
            return
        ids = " ".join(shlex.quote(i) for i in running)
        out = _run(self._target,
                   "docker inspect --format '{{.Id}} {{.State.Pid}}' " + ids,
                   timeout=10)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) != 2 or not parts[1].isdigit():
                continue
            full_id, pid = parts[0], parts[1]
            svc = next((s for sid, s in running.items()
                        if full_id.startswith(sid) or sid.startswith(full_id[:12])), None)
            if not svc or pid == "0":  # 0: it stopped between ps and inspect
                continue
            paths = self._resolve(full_id, pid)
            if paths is _FOREIGN:
                self._go_foreign(svc, pid)
                return
            if paths:
                self._paths[svc] = paths
                self._cid[svc] = full_id[:12]
                self._prev.pop(svc, None)  # new container: fresh CPU baseline
        self.available = bool(self._paths)

    def _go_foreign(self, svc: str, pid: str) -> None:
        """The daemon reported a PID for `svc` that is not that container on
        this host. That happens when docker runs somewhere else than the
        dashboard: Docker Desktop's VM (common on Arch, where docker-desktop
        sets its own `desktop-linux` context), a remote DOCKER_HOST/context,
        or a dashboard running inside its own PID namespace (a container,
        toolbox, flatpak). The PID then names some unrelated host process --
        or none -- so its cgroup counters move with whatever that process does,
        not with the container: graphs with no peak at the exploit or at
        startup. Give up on cgroup sampling for every service rather than mix
        real and bogus series, and let the caller fall back to docker stats."""
        self.foreign = True
        self.available = False
        self._paths.clear()
        self._prev.clear()
        print(f"[resource_stats] {svc}: PID {pid} from docker is not that "
              "container on this host (Docker Desktop VM, remote docker "
              "context or separate PID namespace?) -- sampling via docker "
              "stats instead of cgroup files.", file=sys.stderr)

    def _resolve(self, full_id: str, pid: str):
        """Map a container's host PID to its cgroup CPU/memory stat files by
        reading /proc/<pid>/cgroup -- exact regardless of cgroup driver.

        Returns the paths dict, None when the files can't be found, or
        _FOREIGN when the PID is not this container on this host: every
        docker cgroup driver (cgroupfs "/docker/<id>", systemd
        "docker-<id>.scope", rootless, podman "libpod-<id>.scope") puts the
        full container id in the cgroup path, so a missing PID or an id-less
        path means the daemon's PIDs come from another PID namespace."""
        try:
            with open(f"/proc/{pid}/cgroup", encoding="ascii", errors="replace") as fh:
                cg = fh.read()
        except OSError:
            return _FOREIGN
        if not cgroup_matches_container(cg, full_id):
            return _FOREIGN
        if self._v2:
            m = re.search(r"^0::(.+)$", cg, re.M)
            if not m:
                return None
            base = "/sys/fs/cgroup" + m.group(1).rstrip()
            cpu, mem = os.path.join(base, "cpu.stat"), os.path.join(base, "memory.current")
            if os.path.exists(cpu) and os.path.exists(mem):
                return {"mode": "v2", "cpu": cpu, "mem": mem}
            return None
        cpu_sub = mem_sub = None
        for line in cg.splitlines():
            f = line.split(":")
            if len(f) < 3:
                continue
            ctl, path = f[1], f[2]
            if "cpuacct" in ctl or ctl == "cpu":
                cpu_sub = path
            if ctl == "memory":
                mem_sub = path
        cpu = None
        for cpu_root in ("cpu,cpuacct", "cpuacct"):
            cand = f"/sys/fs/cgroup/{cpu_root}{cpu_sub}/cpuacct.usage" if cpu_sub else None
            if cand and os.path.exists(cand):
                cpu = cand
                break
        mem = f"/sys/fs/cgroup/memory{mem_sub}/memory.usage_in_bytes" if mem_sub else None
        if cpu and mem and os.path.exists(mem):
            return {"mode": "v1", "cpu": cpu, "mem": mem}
        return None

    @staticmethod
    def _read_cpu_ns(paths: dict) -> int | None:
        try:
            with open(paths["cpu"], encoding="ascii", errors="replace") as fh:
                txt = fh.read()
        except OSError:
            return None
        if paths["mode"] == "v2":
            m = re.search(r"usage_usec (\d+)", txt)
            return int(m.group(1)) * 1000 if m else None  # usec -> ns
        try:
            return int(txt.strip())  # cpuacct.usage is already ns
        except ValueError:
            return None

    def sample(self) -> list[tuple[str, float, int]]:
        """(service, cpu_percent, mem_bytes) for each container. CPU% is over
        the interval since the previous sample and may exceed 100% on multi-core
        hosts, exactly like `docker stats`. The first sample reports 0% CPU
        (no prior reading to diff against)."""
        now = time.time()
        out: list[tuple[str, float, int]] = []
        for svc, paths in self._paths.items():
            cpu_ns = self._read_cpu_ns(paths)
            try:
                with open(paths["mem"], encoding="ascii", errors="replace") as fh:
                    mem = int(fh.read().strip())
            except (OSError, ValueError):
                continue
            prev = self._prev.get(svc)
            if cpu_ns is not None:
                self._prev[svc] = (cpu_ns, now)
            if prev and cpu_ns is not None and now > prev[1]:
                cpu_pct = (cpu_ns - prev[0]) / 1e9 / (now - prev[1]) * 100.0
                out.append((svc, max(0.0, cpu_pct), mem))
            else:
                out.append((svc, 0.0, mem))
        return out

    @property
    def cids(self) -> dict[str, str]:
        """{service: short_container_id} for the containers being sampled."""
        return dict(self._cid)

    def log_by_service(self, log_sizes: dict[str, int]) -> dict[str, int]:
        """Map collect_log_sizes()'s {full_id: bytes} onto {service: bytes}."""
        return sizes_by_service(log_sizes, self._cid)


def describe_sampling(sampler: "FastSampler", interval: float) -> str:
    """One line for a report caption saying where CPU/memory samples came from."""
    if sampler.available:
        return f"read from the containers' cgroup files every {interval:g} s"
    if sampler.foreign:
        return ("read with docker stats (~2 s per sample): docker's container "
                "PIDs are not processes on this host (Docker Desktop VM, a remote "
                "docker context or a separate PID namespace), so the cgroup files "
                "can't be used")
    if getattr(sampler, "_target", None) is not None and sampler._target.is_remote:
        return "read with docker stats over SSH (~2 s per sample)"
    return "read with docker stats (~2 s per sample)"


_DOCKER_TS_RE = re.compile(
    r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$")


def parse_docker_time(ts: str) -> float | None:
    """Epoch seconds for a docker timestamp ("2026-10-03T05:08:18.791234567Z",
    nanoseconds and a +hh:mm offset allowed), None if it doesn't parse."""
    import calendar
    m = _DOCKER_TS_RE.match(ts.strip())
    if not m:
        return None
    y, mo, d, h, mi, se, frac, tz = m.groups()
    t = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(se), 0, 0, 0))
    if frac:
        t += float("0." + frac[:9])
    if tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        t -= sign * (int(tz[1:3]) * 3600 + int(tz[4:6]) * 60)
    return t


def parse_health_inspect(text: str, cid_to_svc: dict[str, str]) -> list[tuple[float, str]]:
    """(epoch_start, service) for every health-check run in the output of
    `docker inspect --format '{{.Id}} {{json .State}}' <ids>`. Docker
    keeps the last five runs per container. (The whole .State is asked for
    because a container without a health check has no .State.Health key, and
    naming it in the template fails the entire inspect.)"""
    out: list[tuple[float, str]] = []
    for line in text.splitlines():
        cid, _, js = line.partition(" ")
        svc = next((s for c, s in cid_to_svc.items() if c and cid.startswith(c)), None)
        if not svc or not js.strip() or js.strip() == "null":
            continue
        try:
            health = (json.loads(js) or {}).get("Health") or {}
        except (ValueError, AttributeError):
            continue
        for entry in health.get("Log") or []:
            t = parse_docker_time(entry.get("Start", ""))
            if t is not None:
                out.append((t, svc))
    return sorted(out)


def health_check_times(target: Target, svc_to_cid: dict[str, str],
                       timeout: float = 10.0) -> list[tuple[float, str]]:
    """When each container's Docker health check last ran (its last five runs),
    as (epoch_start, service). A health check is real work inside the
    container (each eshop's check fetches its whole homepage every 30s), so it
    shows up as a CPU spike unrelated to whatever is being measured. []
    on failure."""
    cid_to_svc = {cid: svc for svc, cid in svc_to_cid.items() if cid}
    if not cid_to_svc:
        return []
    ids = " ".join(shlex.quote(c) for c in cid_to_svc)
    text = _run(target, "docker inspect --format '{{.Id}} {{json .State}}' " + ids,
                timeout=timeout)
    return parse_health_inspect(text, cid_to_svc)


def parse_health_schedule(text: str, cid_to_svc: dict[str, str]) -> list[tuple[str, float, float]]:
    """(service, epoch_end_of_last_check, interval_s) per container in the
    output of `docker inspect --format '{{.Id}}|{{json (index .Config "Healthcheck")}}|{{json .State}}'`.
    Docker starts the next check one interval after the previous one ENDS,
    so the next run is at last_end + interval."""
    out: list[tuple[str, float, float]] = []
    for line in text.splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        cid, hc_js, state_js = parts
        svc = next((s for c, s in cid_to_svc.items() if c and cid.startswith(c)), None)
        if not svc:
            continue
        try:
            interval = ((json.loads(hc_js) or {}).get("Interval") or 0) / 1e9
            log = ((json.loads(state_js) or {}).get("Health") or {}).get("Log") or []
        except (ValueError, AttributeError):
            continue
        ends = [t for t in (parse_docker_time(e.get("End", "")) for e in log) if t is not None]
        if interval > 0 and ends:
            out.append((svc, max(ends), interval))
    return out


def health_schedule(target: Target, svc_to_cid: dict[str, str],
                    timeout: float = 10.0) -> list[tuple[str, float, float]]:
    """parse_health_schedule() for the given containers; [] on failure."""
    cid_to_svc = {cid: svc for svc, cid in svc_to_cid.items() if cid}
    if not cid_to_svc:
        return []
    ids = " ".join(shlex.quote(c) for c in cid_to_svc)
    # index, not .Config.Healthcheck: a container without a health check has
    # no such key, and that would fail the whole command.
    text = _run(target, "docker inspect --format "
                "'{{.Id}}|{{json (index .Config \"Healthcheck\")}}|{{json .State}}' " + ids,
                timeout=timeout)
    return parse_health_schedule(text, cid_to_svc)


_REQUEST_LINE_RE = re.compile(r'"([A-Z]+ \S+) HTTP/[\d.]+"')


def parse_access_log(text: str) -> list[tuple[float, str]]:
    """(epoch, "METHOD /target") for each Apache access-log line in
    `docker logs --timestamps` output; other lines are skipped."""
    out: list[tuple[float, str]] = []
    for line in text.splitlines():
        ts, _, rest = line.partition(" ")
        m = _REQUEST_LINE_RE.search(rest)
        t = parse_docker_time(ts) if m else None
        if t is not None:
            out.append((t, m.group(1)))
    return out


def eshop_requests(target: Target, svc_to_cid: dict[str, str], since: float,
                   timeout: float = 10.0) -> list[tuple[float, str, str]]:
    """(epoch, service, "METHOD /target") for every request each eshop
    container (production and honeypot) logged since ``since`` (epoch)."""
    out: list[tuple[float, str, str]] = []
    for svc, cid in svc_to_cid.items():
        if "eshop" not in svc or not cid:
            continue
        text = _run(target, f"docker logs --since {int(since)} --timestamps {shlex.quote(cid)} 2>&1",
                    timeout=timeout)
        out.extend((t, svc, req) for t, req in parse_access_log(text))
    return sorted(out)


def sizes_by_service(log_sizes: dict[str, int], svc_to_cid: dict[str, str]) -> dict[str, int]:
    """Map {full_or_short_id: bytes} onto {service: bytes} using a service->id map."""
    out: dict[str, int] = {}
    for svc, cid in svc_to_cid.items():
        if not cid:
            continue
        for full, sz in log_sizes.items():
            if full.startswith(cid) or cid.startswith(full[:12]):
                out[svc] = sz
                break
    return out


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
