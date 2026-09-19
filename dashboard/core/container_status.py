"""Interpreting `docker compose ps --format json` container records.

One vocabulary for "what state is this container in", shared by the
Services page's per-target summary and the Health diagram's per-node
coloring, so the two can never disagree about e.g. whether a cleanly
exited one-shot job counts as "up".
"""
from __future__ import annotations

from core.colors import GREEN, GREY, ORANGE, RED

# classify() results, in rough severity order.
HEALTHY, RUNNING, UNHEALTHY, EXITED_OK, EXITED_BAD, CREATED, DOWN = (
    "healthy", "running", "unhealthy", "exited_ok", "exited_bad", "created", "down",
)


def exit_code_ok(container: dict) -> bool:
    return str(container.get("ExitCode", "0")) in ("0", "")


def classify(container: dict | None) -> str:
    if container is None:
        return DOWN
    state = container.get("State", "")
    health = container.get("Health", "")
    if state == "running":
        if health == "unhealthy":
            return UNHEALTHY
        if health == "healthy":
            return HEALTHY
        return RUNNING
    if state == "exited":
        return EXITED_OK if exit_code_ok(container) else EXITED_BAD
    if state == "created":
        # `docker compose up` creates every container in the dependency
        # graph up front, then starts them in order -- if that process gets
        # interrupted partway (closed terminal/app, killed mid-command),
        # whatever hasn't started yet is left here indefinitely; it does
        # NOT self-heal, and is otherwise indistinguishable from "down"
        # (not created at all), which reads as "not started on purpose"
        # -- very different from "up got interrupted, re-run it."
        return CREATED
    return DOWN


def is_ready(container: dict | None) -> bool:
    """True once a container is done starting: a one-shot job that exited
    cleanly, or a running container that either has no healthcheck or has
    already passed one. Stricter than classify()==RUNNING, which also
    covers Health=="starting" -- that gap is exactly what a restart
    progress bar needs to show."""
    if container is None:
        return False
    state = container.get("State")
    if state == "exited":
        return exit_code_ok(container)
    return state == "running" and container.get("Health", "") in ("", HEALTHY)


def status_detail(container: dict | None) -> str:
    if container is None:
        return "not created / never started"
    return container.get("Status", container.get("State", "unknown"))


def summarize(containers: list[dict]) -> tuple[str, str]:
    """(summary_text, color) for a whole target's container list.

    A container mid-Start legitimately passes through State=created and
    Health=starting; neither gets special wording (an earlier "created but
    never started -- re-run Start" message was an alarming false positive
    during a normal in-progress Start), they simply don't count as up.
    Run-once services (init_setup, migrations...) end in exited/0 -- their
    successful terminal state -- so they count toward "up" rather than
    leaving a healthy stack permanently at "N/total up"."""
    if not containers:
        return "not running / unreachable", GREY

    counts = {}
    for c in containers:
        status = classify(c)
        counts[status] = counts.get(status, 0) + 1
    total = len(containers)
    healthy = counts.get(HEALTHY, 0)
    unhealthy = counts.get(UNHEALTHY, 0)
    exited_bad = counts.get(EXITED_BAD, 0)
    exited_ok = counts.get(EXITED_OK, 0)
    up = healthy + counts.get(RUNNING, 0) + unhealthy + exited_ok

    if unhealthy or exited_bad:
        return f"{up}/{total} up ({unhealthy} unhealthy, {exited_bad} exited with error)", RED
    if up == total:
        details = []
        if healthy:
            details.append(f"{healthy} healthy")
        if exited_ok:
            details.append(f"{exited_ok} completed")
        detail = f" ({', '.join(details)})" if details else ""
        return f"all {total} up{detail}", GREEN
    if up > 0:
        return f"{up}/{total} up", ORANGE
    return f"0/{total} up", GREY
