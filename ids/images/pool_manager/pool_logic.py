"""Pure decision logic for pool_manager (no Docker, no Redis, no I/O), so it can
be unit-tested with plain `python -m unittest`.

Pool numbering: pools 1..STATIC_POOL_COUNT are declared in docker-compose.yml;
pool_manager only ever creates/destroys numbers above that.
"""
from __future__ import annotations

STATIC_POOL_COUNT = 3  # default; the database layer has 1 compose-declared pool


def next_pool_number(existing: set[int], static_count: int = STATIC_POOL_COUNT) -> int:
    """Smallest runtime pool number (> static_count) not already in use. Reuses
    gaps left by destroyed pools so numbers stay small and DNS names bounded."""
    n = static_count + 1
    while n in existing:
        n += 1
    return n


def pool_cost(mode: str) -> tuple[int, float]:
    """(memory MB, CPUs) one pool reserves, from its containers' limits:
    WordPress layer = eshop (1024 MB, 1 CPU) + database (512 MB, 0.5 CPU);
    database layer = the database alone."""
    return (1536, 1.5) if mode == "wordpress" else (512, 0.5)


def budget_room(total_pools: int, mem_per_pool: float, cpus_per_pool: float,
                max_memory_mb: float, max_cpus: float, max_pools: int) -> tuple[int, str]:
    """How many more pools fit in the resource budget, and what limits it once
    nothing fits ("" while there is room). A limit of 0 means unlimited; the
    pool count is always capped by `max_pools`. `total_pools` counts every pool
    that exists or is being built, compose-declared ones included."""
    room = max_pools - total_pools
    reason = f"pool limit reached: {total_pools} of POOL_MAX={max_pools} pools"
    if max_memory_mb > 0 and mem_per_pool > 0:
        fit = int(max_memory_mb // mem_per_pool) - total_pools
        if fit < room:
            room = fit
            reason = (f"resource limit reached: {total_pools} pools reserve "
                      f"{total_pools * mem_per_pool:.0f} MB of POOL_MAX_MEMORY_MB={max_memory_mb:g}")
    if max_cpus > 0 and cpus_per_pool > 0:
        fit = int(max_cpus / cpus_per_pool + 1e-9) - total_pools
        if fit < room:
            room = fit
            reason = (f"resource limit reached: {total_pools} pools reserve "
                      f"{total_pools * cpus_per_pool:g} CPUs of POOL_MAX_CPUS={max_cpus:g}")
    room = max(0, room)
    return room, ("" if room else reason)


def pools_to_start(free: int, in_flight: int, waiting: int, spares_wanted: int,
                   room: int, parallel: int) -> int:
    """Pools to start now so every session waiting for a pool of its own gets
    one, plus `spares_wanted` unowned pools for the next attackers. Pools being
    built already count; never more than `room` (resource budget) and never
    more than `parallel` builds at once."""
    want = waiting + spares_wanted - free - in_flight
    return max(0, min(want, room, parallel - in_flight))


def stale_owners(owners: set[str], ip_assignments: dict[str, int | None],
                 pool: int) -> set[str]:
    """Owners of `pool` whose assignment has expired or moved elsewhere.
    `ip_assignments` maps owner (session id) -> the pool number its honeypot_pool_session key holds
    now (None when the key is gone)."""
    return {ip for ip in owners if ip_assignments.get(ip) != pool}


def host_pressure(mem_available_mb: float, load1: float, cpus: int, disk_free_gb: float,
                  min_free_mem_mb: float, max_load_per_cpu: float,
                  min_free_disk_gb: float) -> str:
    """Why the host cannot take another pool right now, or "" when it can.
    Memory is checked first: each pool reserves roughly a gigabyte and a half."""
    if mem_available_mb < min_free_mem_mb:
        return (f"low memory: {mem_available_mb:.0f} MB available, "
                f"need {min_free_mem_mb:.0f} MB")
    if cpus > 0 and load1 / cpus > max_load_per_cpu:
        return f"high load: {load1:.2f} on {cpus} CPUs, limit {max_load_per_cpu:g} per CPU"
    if disk_free_gb < min_free_disk_gb:
        return f"low disk: {disk_free_gb:.1f} GB free, need {min_free_disk_gb:g} GB"
    return ""


def idle_action(is_runtime_pool: bool, can_grow: bool, at_max: bool) -> str:
    """What to do with a pool whose attackers have all gone (assignments
    expired): "recycle" (destroy it; a clean spare is rebuilt) only when the
    host has room for a replacement, otherwise "reuse" (hand it to the next
    attacker as it is, which costs no resources). Pools declared in the compose
    file are never destroyed here."""
    if is_runtime_pool and can_grow and not at_max:
        return "recycle"
    return "reuse"
