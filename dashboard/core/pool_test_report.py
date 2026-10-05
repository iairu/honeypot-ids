"""Data and verdict for the Pool test page's PDF report (no Qt, so it is unit
tested on its own; the rendering is core/pool_test_report_pdf.py).

The property under test: by default there is ONE malicious session per
honeypot pool. Two sessions only share a pool when none is free to give --
growth is capped (pool_manager low on memory/CPU/disk) or every ready pool is
already owned -- and the router then reuses the ready pools round-robin.
analyze() turns the frames' session -> pool observations plus the Redis pool
registry into a verdict on exactly that.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# Exploits the report runs, chosen from a live probe of every GET preset (fresh
# session each, up to three attempts): these divert to a honeypot on the FIRST
# request. Per window (A, B, C): a primary exploit and a second, different one;
# FALLBACK are the ones that divert on the 2nd-3rd request, tried only when a
# window's chosen exploit does not divert within MAX_ATTEMPTS. Presets that never
# divert in three attempts (time-based blind SQLi, wordlist scans, IDOR walks)
# are deliberately absent. test_pool_test_report checks every CVE exists.
EXPLOIT_PLAN = [("CVE-2024-2387", "CVE-2024-1071"),     # A: SQL injection
                ("CVE-2025-47577", "CVE-2025-4403"),    # B: file-upload RCE
                ("GENERIC-WP-003", "GENERIC-WP-002")]   # C: user enumeration / installer
FALLBACK_EXPLOITS = ["CVE-2024-27956", "CVE-2022-0739", "CVE-2024-2879", "CVE-2023-2986",
                     "CVE-2025-2266", "GENERIC-SQLI-001", "GENERIC-XSS-001", "GENERIC-XSS-002",
                     "GENERIC-WP-001"]
MAX_ATTEMPTS = 3

EXCLUSIVE = "exclusive"
SHARED_EXPECTED = "shared_expected"
SHARED_UNEXPECTED = "shared_unexpected"
MERGED = "merged"
INCOMPLETE = "incomplete"
UNSTABLE = "unstable"


@dataclass
class FrameResult:
    label: str
    user_agent: str = ""
    language: str = ""
    url: str = ""
    session_id: str = ""          # "" -> the proxy never set a session cookie
    pool: int | None = None       # None -> session not bound to any pool
    screenshot: Any = None        # QImage of the frame, or None


@dataclass
class Decision:
    """The router's current decision for one session, read back from Redis."""
    session_id: str = ""
    route: str = "NO SESSION"     # "PRODUCTION" | "HONEYPOT" | "NO SESSION"
    score: int | None = None
    reason: str = ""
    pool: int | None = None

    def text(self) -> str:
        if self.route == "NO SESSION":
            return "No session yet"
        out = f"Routed to {self.route}"
        if self.pool is not None:
            out += f" \u2022 pool {self.pool}"
        if self.score is not None:
            out += f" \u2022 score {self.score}"
        if self.reason and self.route == "HONEYPOT":
            out += f" \u2022 {self.reason}"
        return out


def parse_decision(session_id: str, session_json: str, pool_text: str) -> Decision:
    """Decision from the session:<id> record and honeypot_pool_session:<id>
    value (either may be empty/unparseable -> that part is simply unknown)."""
    if not session_id:
        return Decision()
    try:
        rec = json.loads(session_json) if session_json.strip() else {}
    except ValueError:
        rec = {}
    pool = int(pool_text) if pool_text.strip().isdigit() else None
    if not isinstance(rec, dict):
        rec = {}
    score = rec.get("threat_score")
    bound = bool(rec.get("honeypot_bound")) or pool is not None
    return Decision(
        session_id=session_id,
        route="HONEYPOT" if bound else "PRODUCTION",
        score=int(score) if isinstance(score, (int, float)) else None,
        reason=str(rec.get("honeypot_reason") or ""),
        pool=pool)


@dataclass
class StepResult:
    """One scripted step: what each window did, and each session's decision after."""
    title: str
    detail: str
    actions: list[str]            # per frame: what that window did this step
    decisions: list[Decision]     # per frame, read after the step settled
    shots: list[Any] = field(default_factory=list)   # per frame QImage


def sticky_violations(steps: list[StepResult]) -> list[str]:
    """A session bound to a pool must keep that pool for the rest of the run."""
    out = []
    seen: dict[int, int] = {}
    for step in steps:
        for i, d in enumerate(step.decisions):
            if d.pool is None:
                continue
            if i in seen and seen[i] != d.pool:
                out.append(f"Window {i + 1} moved from pool {seen[i]} to pool {d.pool} "
                           f"during '{step.title}'.")
            seen[i] = d.pool
    return out


@dataclass
class ExploitRun:
    """One exploit a window ran: how many attempts it took to be diverted."""
    window: str
    cve: str
    name: str
    attempts: int
    diverted: bool
    pool: int | None
    replaced: bool = False        # picked because an earlier choice never diverted


@dataclass
class PoolTestData:
    generated_at: str
    target_label: str
    base_url: str
    exploit: str
    frames: list[FrameResult]
    pool_state: dict = field(default_factory=dict)   # redis_inspect.pool_state()
    steps: list[StepResult] = field(default_factory=list)
    runs: list[ExploitRun] = field(default_factory=list)
    evidence: list[Any] = field(default_factory=list)   # pool_evidence.ContainerEvidence
    since: str = ""


@dataclass
class Verdict:
    status: str
    headline: str
    findings: list[str]
    by_pool: dict[int, list[str]]   # pool -> labels of the frames bound to it


def sharing_justified(state: dict) -> bool:
    """Whether the registry explains sessions sharing a pool: growth capped, or
    no free pool and every ready pool already owned (round-robin reuse)."""
    if not state:
        return False
    if state.get("capped"):
        return True
    owners = state.get("owners", {})
    ready = state.get("ready", [])
    return not state.get("free") and bool(ready) and all(owners.get(n, 0) >= 1 for n in ready)


def analyze(frames: list[FrameResult], state: dict, steps: list[StepResult] | None = None) -> Verdict:
    by_pool: dict[int, list[str]] = {}
    for f in frames:
        if f.pool is not None:
            by_pool.setdefault(f.pool, []).append(f.label)

    seen: dict[str, str] = {}
    merged: list[str] = []
    for f in frames:
        if f.session_id and f.session_id in seen:
            merged.append(f"{seen[f.session_id]} and {f.label}")
        elif f.session_id:
            seen[f.session_id] = f.label
    if merged:
        return Verdict(MERGED, "Frames were merged into one session", [
            f"{pair} hold the same session id, so they are one attacker, not two."
            for pair in merged
        ] + ["Each frame needs its own cookie jar and browser fingerprint "
             "(User-Agent / Accept-Language); check that the frames were reset with "
             "'New sessions' before the run."], by_pool)

    missing = [f.label for f in frames if not f.session_id]
    unbound = [f.label for f in frames if f.session_id and f.pool is None]
    if missing or unbound:
        findings = []
        if missing:
            findings.append("No session cookie yet: " + ", ".join(missing)
                            + " (open the shop in that frame first).")
        if unbound:
            findings.append("Session not bound to a pool: " + ", ".join(unbound)
                            + " (the attack has not pushed its score over the diversion "
                              "threshold, or has not been sent).")
        return Verdict(INCOMPLETE, "Not every frame reached a honeypot pool", findings, by_pool)

    moved = sticky_violations(steps or [])
    unstable = bool(moved)
    if steps and any(d.route == "HONEYPOT" for d in steps[0].decisions):
        moved.append("Some windows were already diverted before attacking (step 1): the host "
                     "IP carries bad reputation from earlier tests. Use 'Unpoison host IP' on "
                     "the Exploits page and run the report again.")
    shared = {n: labels for n, labels in by_pool.items() if len(labels) > 1}
    if not shared:
        pools = ", ".join(f"{f.label} → pool {f.pool}" for f in frames)
        if unstable:
            return Verdict(UNSTABLE, "Pools are exclusive but an attacker changed pool",
                           [pools + "."] + moved, by_pool)
        return Verdict(EXCLUSIVE, "Every attacker has a honeypot pool of their own",
                       [pools + "."] + moved, by_pool)

    findings = [f"Pool {n} is shared by {', '.join(labels)}." for n, labels in sorted(shared.items())]
    if sharing_justified(state):
        reason = (f"pool growth is capped ({state.get('capped')})" if state.get("capped")
                  else "no free pool was left, so new attackers were assigned to the "
                       "ready pools round-robin")
        return Verdict(SHARED_EXPECTED, "Pools are shared, as expected under resource pressure",
                       findings + [f"This is the designed fallback: {reason}."] + moved, by_pool)
    free = state.get("free", []) if state else []
    findings.append(
        "Sharing is only the designed fallback when no pool is free or growth is capped, "
        + (f"but spare pool(s) {', '.join(map(str, free))} were free and growth is not capped."
           if free else "but the registry shows no reason for it (state unavailable or pools missing)."))
    return Verdict(SHARED_UNEXPECTED, "Pools are shared although free pools exist",
                   findings + moved, by_pool)
