"""Pure decision logic for pool_manager (no Docker, no Redis, no I/O), so it can
be unit-tested with plain `python -m unittest`.

Pool numbering: pools 1..STATIC_POOL_COUNT are declared in docker-compose.yml;
pool_manager only ever creates/destroys numbers above that.
"""
from __future__ import annotations

STATIC_POOL_COUNT = 3


def next_pool_number(existing: set[int], static_count: int = STATIC_POOL_COUNT) -> int:
    """Smallest runtime pool number (> static_count) not already in use. Reuses
    gaps left by destroyed pools so numbers stay small and DNS names bounded."""
    n = static_count + 1
    while n in existing:
        n += 1
    return n


def spares_needed(free: int, in_flight: int, spares_wanted: int,
                  total_pools: int, max_pools: int) -> int:
    """How many more pools to start so `spares_wanted` unowned pools are ready
    (or on their way), without ever exceeding `max_pools` in total."""
    want = spares_wanted - free - in_flight
    room = max_pools - total_pools - in_flight
    return max(0, min(want, room))


def stale_owners(owners: set[str], ip_assignments: dict[str, int | None],
                 pool: int) -> set[str]:
    """Owners of `pool` whose assignment has expired or moved elsewhere.
    `ip_assignments` maps IP -> the pool number its honeypot_pool_ip key holds
    now (None when the key is gone)."""
    return {ip for ip in owners if ip_assignments.get(ip) != pool}
