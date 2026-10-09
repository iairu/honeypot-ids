"""Data and verdict for the Segmentation Validation page's PDF report (no Qt, so it is unit
tested on its own; the rendering is core/pool_test_report_pdf.py).

The property under test: by default there is ONE malicious session per
honeypot pool. The pools scale with the number of attacker sessions: a session
that finds no free pool borrows one round-robin until pool_manager has built its
own, then moves there. Two sessions only keep sharing a pool once growth is
capped (the pools' resource budget or POOL_MAX is reached, or the host is low on
memory/CPU/disk) -- the router then reuses the ready pools round-robin.
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

# How many test windows the Segmentation Validation page can run side by side.
MIN_WINDOWS, MAX_WINDOWS = 3, 10

# What each window puts in its cart before anything is attacked: (product slug,
# quantity). Simple products only, so a plain ?add-to-cart= request is enough.
CART_PLAN = [[("ceramic-pour-over-dripper", 1), ("paper-filters-size-02", 2)],
             [("hand-burr-coffee-grinder", 1), ("stainless-milk-pitcher", 1)],
             [("enamel-camp-mug", 2), ("fernhill-canvas-tote", 1)],
             [("gooseneck-electric-kettle", 1), ("logo-cap", 2)],
             [("digital-brew-scale", 1)],
             [("glass-french-press", 1), ("barista-apron", 1)],
             [("glass-bean-canister", 2)],
             [("double-wall-glass-cups", 2)],
             [("insulated-travel-tumbler", 1)],
             [("coffee-lover-gift-box", 1), ("pour-over-starter-kit", 1)]]

# What a window that is not attacking looks at meanwhile, like a shopper would:
# (path, what the report calls it). Read-only pages only -- nothing here may
# change a cart or log anyone in.
BROWSE_PAGES = [("/product/kenya-nyeri-aa/", "Kenya Nyeri AA"),
                ("/terms-of-service/", "the Terms of Service"),
                ("/product-category/brewing-gear/", "Brewing Gear"),
                ("/product/glass-french-press/", "Glass French Press"),
                ("/shipping-returns/", "Shipping & Returns"),
                ("/product/ethiopia-guji-natural/", "Ethiopia Guji Natural"),
                ("/product-category/drinkware/", "Drinkware"),
                ("/faq/", "the FAQ"),
                ("/product/stoneware-mug/", "Stoneware Mug"),
                ("/privacy-policy/", "the Privacy Policy"),
                ("/product/coffee-club-subscription/", "Coffee Club Subscription"),
                ("/product-category/coffee/", "Coffee Beans"),
                ("/about/", "Our Story"),
                ("/product/sunrise-espresso-blend/", "Sunrise Espresso")]


def browse_page(window: int, visit: int) -> tuple[str, str]:
    """The `visit`-th page window `window` browses while it has nothing else to
    do. Windows start at different points of BROWSE_PAGES, so they look at
    different things at the same time."""
    return BROWSE_PAGES[(window * 3 + visit) % len(BROWSE_PAGES)]


def browse_action(labels: list[str]) -> str:
    """Report text for the pages a window looked at during one step."""
    if not labels:
        return "Browses the shop"
    seen = list(dict.fromkeys(labels))
    return "Looks at " + ", ".join(seen)


def window_plan(windows: int) -> list[tuple[str, str]]:
    """(first, second) exploit per window. Windows A-C use EXPLOIT_PLAN; further
    windows open with a fallback exploit (a different one each while they last)
    and run one of A-C's second exploits afterwards -- separate sessions, so a
    repeat across windows does not matter there."""
    plan = list(EXPLOIT_PLAN[:windows])
    for w in range(len(plan), windows):
        k = w - len(EXPLOIT_PLAN)
        plan.append((FALLBACK_EXPLOITS[k % len(FALLBACK_EXPLOITS)],
                     EXPLOIT_PLAN[k % len(EXPLOIT_PLAN)][1]))
    return plan

EXCLUSIVE = "exclusive"
SHARED_EXPECTED = "shared_expected"
SHARED_UNEXPECTED = "shared_unexpected"
MERGED = "merged"
INCOMPLETE = "incomplete"
UNSTABLE = "unstable"
CART_LOST = "cart_lost"
TAMPER_MISSED = "tamper_missed"


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
    waiting: bool = False         # borrowing `pool` until its own pool is built

    def text(self) -> str:
        if self.route == "NO SESSION":
            return "No session yet"
        out = f"Routed to {self.route}"
        if self.pool is not None:
            out += f" \u2022 pool {self.pool}"
            if self.waiting:
                out += " (borrowed, own pool being built)"
        if self.score is not None:
            out += f" \u2022 score {self.score}"
        if self.reason and self.route == "HONEYPOT":
            out += f" \u2022 {self.reason}"
        return out


def parse_decision(session_id: str, session_json: str, pool_text: str,
                   waiting_text: str = "") -> Decision:
    """Decision from the session:<id> record, honeypot_pool_session:<id> value
    and the session's score in honeypot_pool:waiting (any may be empty or
    unparseable -> that part is simply unknown)."""
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
        pool=pool, waiting=pool is not None and bool(waiting_text.strip()))


@dataclass
class CartState:
    """A window's cart as the shop reports it (WooCommerce Store API)."""
    items: list[tuple[str, int]] = field(default_factory=list)   # (product name, quantity)
    total: str = ""

    def signature(self) -> tuple:
        return tuple(sorted(self.items))

    def text(self) -> str:
        if not self.items:
            return "Cart empty"
        n = sum(q for _n, q in self.items)
        return f"Cart: {n} item{'s' if n != 1 else ''}" + (f" \u2022 {self.total}" if self.total else "")


def parse_cart(store_api_json: str) -> CartState | None:
    """CartState from a /wp-json/wc/store/v1/cart response; None if unreadable."""
    try:
        d = json.loads(store_api_json)
        minor = int(d["totals"].get("currency_minor_unit", 2))
        cents = int(d["totals"]["total_price"])
        sym = d["totals"].get("currency_prefix", "$")
        return CartState([(i["name"], int(i["quantity"])) for i in d["items"]],
                         f"{sym}{cents / 10 ** minor:,.{minor}f}")
    except (ValueError, KeyError, TypeError):
        return None


# ---- session tampering ------------------------------------------------------
#
# With tampering on, the run makes random windows attack their own session
# between steps, the way an attacker would try to shed or swap it:
#   DELETE  clear the session cookie and/or the browser storage. The proxy must
#           re-identify the window by its passive fingerprint and hand it back
#           the SAME session (and so the same pool).
#   FORGE   rewrite the session cookie (and localStorage) to a session the
#           server never signed. The proxy must reject it as not server-signed
#           (session_cookie_rejections in Redis) and never serve the claimed
#           session -- in particular not another window's.

DELETE, FORGE = "delete", "forge"
TAMPER_KINDS = (DELETE, FORGE)

# Variants, picked at random per event: (key, report text).
DELETE_VARIANTS = [("session_cookie", "deleted its SERVERID session cookie"),
                   ("storage", "cleared its localStorage and sessionStorage"),
                   ("all", "cleared all site data (every cookie, localStorage, sessionStorage)")]
FORGE_VARIANTS = [("invented", "rewrote its session to an invented session id with a made-up signature"),
                  ("hijack", "rewrote its session to another window's session id with a made-up signature"),
                  ("unsigned", "stripped the signature off its own session id")]
VARIANT_TEXT = dict(DELETE_VARIANTS + FORGE_VARIANTS)

# Chance that a step in the tampering phase gets a tamper event.
TAMPER_CHANCE = 0.5


def tamper_schedule(steps: list[int], kinds: list[str], rng) -> dict[int, list[str]]:
    """{step number: [kind, ...]} -- which tampering happens before which step.
    Each step gets one event with TAMPER_CHANCE; every enabled kind is then
    guaranteed at least one event, so the report always has evidence for it."""
    if not steps or not kinds:
        return {}
    out: dict[int, list[str]] = {}
    for n in steps:
        if rng.random() < TAMPER_CHANCE:
            out.setdefault(n, []).append(rng.choice(kinds))
    for kind in kinds:
        if not any(kind in ks for ks in out.values()):
            out.setdefault(rng.choice(steps), []).append(kind)
    return out


@dataclass
class TamperEvent:
    """One tampering a window did to its own session, and what the proxy made of it."""
    t: float                      # seconds since the run started
    window: int
    step: int                     # index into PoolTestData.steps of the step it happened in
    kind: str                     # DELETE | FORGE
    variant: str                  # a key of DELETE_VARIANTS / FORGE_VARIANTS
    before_session: str           # the window's genuine session id
    before_pool: int | None = None
    planted: str = ""             # FORGE: the cookie value written into the window
    claimed_session: str = ""     # FORGE: the other session that cookie claimed ("" for
                                  # "unsigned", which claims the window's own id)
    victim: int | None = None     # FORGE hijack: the window whose session was claimed
    after_session: str = ""       # session id the proxy handed the window afterwards
    after_pool: int | None = None
    resolved: bool = False        # the window has loaded a page since, and was read back
    rejected: bool | None = None  # FORGE: found in the proxy's rejected-cookie log
    rejection_status: str = ""    # "bad_signature" | "malformed"
    scored: bool | None = None    # FORGE: rejection scored as tampering (stable signing key)
    score: int = 0

    def reidentified(self) -> bool:
        """Back in its own session: the fingerprint (or the untouched cookie) won."""
        return bool(self.before_session) and self.after_session == self.before_session

    def caught(self) -> bool:
        if not self.resolved:
            return False
        if self.kind == DELETE:
            return self.reidentified()
        # A forged session must be rejected and never served.
        return bool(self.rejected) and not (self.claimed_session
                                            and self.after_session == self.claimed_session)

    def what(self) -> str:
        text = VARIANT_TEXT.get(self.variant, self.variant)
        if self.kind == FORGE and self.victim is not None:
            text = text.replace("another window's", f"window {self.victim + 1}'s")
        return text

    def outcome(self) -> str:
        """Plain-language result for the report."""
        if not self.resolved:
            return "not checked: the window loaded no page after it before the run ended"
        if self.kind == DELETE:
            if self.reidentified():
                return ("re-identified: handed back its own session"
                        + (f" (pool {self.after_pool})" if self.after_pool is not None else ""))
            if not self.after_session:
                return "MISSED: the window got no session back"
            return "MISSED: the window was given a new session, its old one was lost"
        parts = []
        if self.rejected:
            parts.append(f"rejected as not server-signed ({self.rejection_status.replace('_', ' ')})")
            if self.scored:
                parts.append(f"scored as tampering (+{self.score})")
        else:
            parts.append("MISSED: the proxy never logged the cookie as rejected")
        if self.claimed_session and self.after_session == self.claimed_session:
            parts.append("MISSED: the proxy served the forged session")
        elif self.reidentified():
            parts.append("re-identified to its own session")
        elif self.after_session:
            parts.append("given a new session")
        return "; ".join(parts)


def parse_rejections(lines: list[str]) -> list[dict]:
    """The proxy's rejected-cookie log (session_cookie_rejections, one JSON per line)."""
    out = []
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and r.get("cookie_sha1"):
            out.append(r)
    return out


def match_rejection(planted: str, rejections: list[dict]) -> dict | None:
    """The log entry for the cookie value a window planted, if the proxy logged it."""
    import hashlib
    digest = hashlib.sha1(planted.encode()).hexdigest()
    return next((r for r in rejections if r.get("cookie_sha1") == digest), None)


def cart_resets(tamper: list[TamperEvent] | None) -> set[tuple[int, int]]:
    """(step index, window) where the window wiped all its site data: WooCommerce's
    own cart cookie went with it, so an emptied cart there is expected."""
    return {(e.step, e.window) for e in tamper or [] if e.kind == DELETE and e.variant == "all"}


def tamper_findings(tamper: list[TamperEvent] | None) -> list[str]:
    """One line per tampering the proxy did not catch."""
    return [f"Window {e.window + 1} {e.what()} and the stack did not catch it: {e.outcome()}."
            for e in tamper or [] if e.resolved and not e.caught()]


def cart_violations(steps: list["StepResult"], resets: set[tuple[int, int]] | None = None) -> list[str]:
    """Carts must stay exactly as filled, however the session is routed. The
    baseline is each window's cart in the first step that has one, and starts
    over where `resets` (see cart_resets()) says the window wiped its cookies."""
    out = []
    base: dict[int, tuple[CartState, str]] = {}
    for n, step in enumerate(steps):
        for i, c in enumerate(step.carts):
            if resets and (n, i) in resets:
                base.pop(i, None)
            if c is None:
                if i in base:
                    out.append(f"Window {i + 1}: cart could not be read in '{step.title}'.")
                continue
            if i not in base:
                if c.items:
                    base[i] = (c, step.title)
                continue
            if c.signature() != base[i][0].signature():
                now = c.text() if c.items else "empty"
                out.append(f"Window {i + 1}: cart changed in '{step.title}' ({now}) "
                           f"from what it held in '{base[i][1]}' ({base[i][0].text()}).")
    return out


def parse_product_ids(store_api_json: str, slugs: list[str]) -> dict[str, int]:
    """{slug: product id} from a Store API products response; raises when one is missing."""
    try:
        found = {p["slug"]: int(p["id"]) for p in json.loads(store_api_json or "[]")}
    except (ValueError, KeyError, TypeError):
        found = {}
    missing = [s for s in slugs if s not in found]
    if missing:
        raise RuntimeError(f"Could not find product(s) {', '.join(missing)} on the shop.")
    return {s: found[s] for s in slugs}


@dataclass
class StepResult:
    """One scripted step: what each window did, and each session's decision after."""
    title: str
    detail: str
    actions: list[str]            # per frame: what that window did this step
    decisions: list[Decision]     # per frame, read after the step settled
    shots: list[Any] = field(default_factory=list)   # per frame QImage
    carts: list[CartState | None] = field(default_factory=list)   # per frame, read after the step


def sticky_violations(steps: list[StepResult]) -> list[str]:
    """A session bound to a pool must keep that pool for the rest of the run.
    The one allowed move: off a pool it only borrowed (waiting) while its own
    was being built."""
    out = []
    seen: dict[int, Decision] = {}
    for step in steps:
        for i, d in enumerate(step.decisions):
            if d.pool is None:
                continue
            prev = seen.get(i)
            if prev is not None and prev.pool != d.pool and not prev.waiting:
                out.append(f"Window {i + 1} moved from pool {prev.pool} to pool {d.pool} "
                           f"during '{step.title}'.")
            seen[i] = d
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


# Where a window's session is served at one moment (see classify()).
PRODUCTION, OWN, BORROWED, SHARED = "production", "own", "borrowed", "shared"
STATES = (PRODUCTION, OWN, BORROWED, SHARED)


@dataclass
class Sample:
    """One window's routing at one moment of the run (seconds since its start).
    Samples taken together (one read of every window) share the same `t`."""
    t: float
    window: int
    session_id: str
    route: str
    pool: int | None
    waiting: bool


@dataclass
class LoadTiming:
    """How long one page load took in one window, and where it was served."""
    t: float                      # seconds since the run started (load start)
    window: int
    step: str
    ms: float
    state: str = ""               # filled from the routing read right after the load


@dataclass
class UsageSample:
    """All honeypot pool containers' resource use at one moment of the run."""
    t: float
    containers: int
    pools: int
    mem_mb: float
    cpu_percent: float


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
    # Scaling / latency (all times in seconds since the run started).
    duration: float = 0.0
    delayed: int = 0              # windows that attacked only after pools were pre-built
    samples: list[Sample] = field(default_factory=list)
    loads: list[LoadTiming] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)  # pool_manager events, `at` rebased
    marks: list[tuple[float, str]] = field(default_factory=list)   # (t, step title)
    reserve: dict = field(default_factory=dict)       # see ScalingSummary.reserve
    usage: list[UsageSample] = field(default_factory=list)
    # The forced scale-down at the end: {"requested", "done" (None = timed out),
    # "sessions", "pools_before", "pools_after", "idle_timeout"}
    scaledown: dict = field(default_factory=dict)
    # Session tampering (empty when it was switched off).
    tamper: list[TamperEvent] = field(default_factory=list)
    tamper_kinds: list[str] = field(default_factory=list)   # what was switched on
    tamper_seed: int | None = None


def classify(batch: list[Sample]) -> list[str]:
    """State of each sample in one simultaneous read of the windows:
    production, borrowed (sharing a pool only until its own is built), shared
    (with another test window, for good) or own."""
    out = []
    for s in batch:
        if s.route != "HONEYPOT" or s.pool is None:
            out.append(PRODUCTION)
        elif s.waiting:
            out.append(BORROWED)
        elif any(o is not s and o.pool == s.pool and o.route == "HONEYPOT" and not o.waiting
                 for o in batch):
            out.append(SHARED)
        else:
            out.append(OWN)
    return out


def timelines(samples: list[Sample], end: float) -> dict[int, list[tuple[float, float, str, int | None]]]:
    """Per window: (start, end, state, pool) segments, consecutive equal
    states merged; the last one runs until `end`."""
    batches: dict[float, list[Sample]] = {}
    for smp in samples:
        batches.setdefault(smp.t, []).append(smp)
    out: dict[int, list] = {}
    for t in sorted(batches):
        batch = batches[t]
        for smp, state in zip(batch, classify(batch)):
            segs = out.setdefault(smp.window, [])
            pool = smp.pool if state != PRODUCTION else None
            if segs and segs[-1][2] == state and segs[-1][3] == pool:
                continue
            if segs:
                segs[-1] = (segs[-1][0], t, segs[-1][2], segs[-1][3])
            segs.append((t, end, state, pool))
    for segs in out.values():
        if segs:
            segs[-1] = (segs[-1][0], max(end, segs[-1][0]), segs[-1][2], segs[-1][3])
    return out


def _quantile(values: list[float], q: float) -> float:
    v = sorted(values)
    if not v:
        return 0.0
    k = (len(v) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def load_stats(loads: list[LoadTiming]) -> dict[str, dict]:
    """Page-load latency per routing state: n, median, p90, max (ms)."""
    out = {}
    for state in STATES:
        ms = [x.ms for x in loads if x.state == state]
        if ms:
            out[state] = {"n": len(ms), "median": _quantile(ms, 0.5),
                          "p90": _quantile(ms, 0.9), "max": max(ms)}
    return out


@dataclass
class PoolBuild:
    pool: int
    start: float
    seconds: float | None         # None -> still building when the run ended
    ok: bool
    reason: str = ""              # "waiting session" | "reserve" | "spare"
    phases: list[tuple[str, float]] = field(default_factory=list)
    error: str = ""


@dataclass
class BorrowCase:
    """Case A: a window that found no free pool (not scaled yet) and borrowed one."""
    window: int
    borrowed: int | None
    start: float
    end: float | None             # moved to its own pool / dropped / None = still waiting
    outcome: str                  # "own" | "dropped" | "waiting"
    own_pool: int | None = None
    waited: float | None = None   # pool_manager's figure when it handed the pool over


@dataclass
class LimitCase:
    """Case B: a window left on a shared pool because the resource limit was hit."""
    window: int
    pool: int | None
    since: float
    shared_with: list[int]
    how: str                      # "assigned while capped" | "dropped from the wait queue"


@dataclass
class PoolRemoval:
    pool: int
    at: float                     # removal finished
    seconds: float                # time to remove its containers and volumes
    idle: float | None            # seconds since a request last reached it
    forced: bool                  # requested scale-down, not the idle timeout


@dataclass
class ScalingSummary:
    builds: list[PoolBuild]
    borrow: list[BorrowCase]
    limit: list[LimitCase]
    capped: list[tuple[float, str]]        # (t, reason) each time growth got capped
    reserve: dict                          # {"requested", "start", "reached", "end", "free", "reason"}
    timelines: dict[int, list]
    removals: list[PoolRemoval] = field(default_factory=list)
    released: list[tuple[float, int, int, str]] = field(default_factory=list)  # (t, pool, sessions, reason)


def usage_at(usage: list[UsageSample], t: float, after: bool = False) -> UsageSample | None:
    """The last sample at or before `t` (or, with after=True, the first at or after it)."""
    if after:
        return next((u for u in sorted(usage, key=lambda u: u.t) if u.t >= t), None)
    return next((u for u in sorted(usage, key=lambda u: -u.t) if u.t <= t), None)


def _arrival(segs: list, pool: int | None) -> float:
    """When a window's timeline first reached `pool` (inf if never)."""
    return next((sg[0] for sg in segs if sg[3] == pool), float("inf"))


def scaling_summary(data: PoolTestData) -> ScalingSummary:
    """Pool builds, case A (borrowed while scaling) and case B (shared at the
    resource limit) from the samples and pool_manager's event log."""
    starts = {}
    builds: list[PoolBuild] = []
    capped: list[tuple[float, str]] = []
    handoffs: dict[str, dict] = {}
    dropped: dict[str, float] = {}
    intervals: list[list] = []             # [capped at, uncapped at or None]
    removals: list[PoolRemoval] = []
    released: list[tuple[float, int, int, str]] = []
    for e in sorted(data.events, key=lambda e: e.get("at", 0)):
        kind = e.get("type")
        if kind == "build_start":
            starts[e.get("pool")] = e
        elif kind == "build":
            b = starts.pop(e.get("pool"), {})
            builds.append(PoolBuild(int(e.get("pool", 0)), float(e.get("start", e["at"])),
                                    float(e.get("seconds", 0)), bool(e.get("ok")),
                                    b.get("reason", ""),
                                    [(str(n), float(sec)) for n, sec in e.get("phases", [])],
                                    str(e.get("error", ""))))
        elif kind == "capped":
            capped.append((float(e["at"]), str(e.get("reason", ""))))
            intervals.append([float(e["at"]), None])
        elif kind == "uncapped" and intervals and intervals[-1][1] is None:
            intervals[-1][1] = float(e["at"])
        elif kind == "handoff":
            handoffs[str(e.get("session"))] = e
        elif kind == "scaledown":
            removals.append(PoolRemoval(int(e.get("pool", 0)), float(e["at"]),
                                        float(e.get("seconds", 0)),
                                        e.get("idle"), bool(e.get("forced"))))
        elif kind == "released":
            released.append((float(e["at"]), int(e.get("pool", 0)),
                             len(e.get("sessions", [])), str(e.get("reason", ""))))
        elif kind == "dropped_waiting":
            for sid in e.get("sessions", []):
                dropped[str(sid)] = float(e["at"])
    for pool, e in starts.items():   # started during the run, not finished
        builds.append(PoolBuild(int(pool), float(e["at"]), None, False, e.get("reason", "")))
    builds.sort(key=lambda b: b.start)

    tl = timelines(data.samples, data.duration)
    sid_of: dict[int, str] = {}
    for smp in data.samples:
        if smp.session_id:
            sid_of[smp.window] = smp.session_id
    borrow: list[BorrowCase] = []
    limit: list[LimitCase] = []
    for w, segs in sorted(tl.items()):
        sid = sid_of.get(w, "")
        for i, (t0, t1, state, pool) in enumerate(segs):
            if state != BORROWED or (i and segs[i - 1][2] == BORROWED):
                continue
            nxt = next((sg for sg in segs[i + 1:] if sg[2] != BORROWED), None)
            h = handoffs.get(sid)
            if nxt is not None and nxt[2] == OWN:
                borrow.append(BorrowCase(w, pool, t0, nxt[0], "own", nxt[3],
                                         h.get("waited") if h else None))
            elif nxt is not None or sid in dropped:
                borrow.append(BorrowCase(w, pool, t0, dropped.get(sid, nxt[0] if nxt else None),
                                         "dropped"))
            else:
                borrow.append(BorrowCase(w, pool, t0, None, "waiting"))
        final = segs[-1] if segs else None
        first = next((sg for sg in segs if sg[2] != PRODUCTION), None)
        # Diverted while growth was capped: round-robin onto a ready pool, even
        # when the pool's other owner is not one of the test windows.
        capped_at_divert = first is not None and first[2] in (OWN, SHARED) and any(
            a - 1 <= first[0] and (b is None or first[0] <= b) for a, b in intervals)
        # Shared at the end: the round-robin newcomer is whoever reached that
        # pool last (the first one there owned it), even if the cap predates
        # the run and so has no event in it.
        arrived_later = final is not None and final[2] == SHARED and any(
            o != w and sg and sg[-1][3] == final[3] and _arrival(sg, final[3]) < _arrival(segs, final[3])
            for o, sg in tl.items())
        if final and (arrived_later or capped_at_divert or (sid in dropped and final[2] != OWN)):
            others = sorted({o for o, sg in tl.items() if o != w and sg and sg[-1][3] == final[3]
                             and sg[-1][2] in (SHARED, OWN, BORROWED)})
            how = "dropped from the wait queue" if sid in dropped else "assigned while capped"
            limit.append(LimitCase(w, final[3], first[0] if first else final[0], others, how))
    return ScalingSummary(builds, borrow, limit, capped, dict(data.reserve), tl,
                          removals, released)


@dataclass
class Verdict:
    status: str
    headline: str
    findings: list[str]
    by_pool: dict[int, list[str]]   # pool -> labels of the frames bound to it


def sharing_justified(state: dict) -> bool:
    """Whether the registry explains sessions sharing a pool: growth capped,
    sessions still waiting for pools being built, or no free pool and every
    ready pool already owned (round-robin reuse)."""
    if not state:
        return False
    if state.get("capped") or state.get("waiting"):
        return True
    owners = state.get("owners", {})
    ready = state.get("ready", [])
    return not state.get("free") and bool(ready) and all(owners.get(n, 0) >= 1 for n in ready)


def analyze(frames: list[FrameResult], state: dict, steps: list[StepResult] | None = None,
            tamper: list[TamperEvent] | None = None) -> Verdict:
    by_pool: dict[int, list[str]] = {}
    for f in frames:
        if f.pool is not None:
            by_pool.setdefault(f.pool, []).append(f.label)

    # First: a forged session the proxy accepted also shows up as a merge or a
    # pool change below, and this says why.
    missed = tamper_findings(tamper)
    if missed:
        pools = ", ".join(f"{f.label} \u2192 pool {f.pool}" for f in frames)
        return Verdict(TAMPER_MISSED, "A tampered session was not caught",
                       missed + [pools + "."] + sticky_violations(steps or []), by_pool)

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
                     "the Attack Simulation page and run the report again.")
    cart_issues = cart_violations(steps or [], cart_resets(tamper))
    shared = {n: labels for n, labels in by_pool.items() if len(labels) > 1}
    if not shared and cart_issues:
        pools = ", ".join(f"{f.label} \u2192 pool {f.pool}" for f in frames)
        return Verdict(CART_LOST, "A cart changed when its session was routed to a honeypot",
                       [pools + "."] + cart_issues + moved, by_pool)
    if not shared:
        pools = ", ".join(f"{f.label} → pool {f.pool}" for f in frames)
        if unstable:
            return Verdict(UNSTABLE, "Pools are exclusive but an attacker changed pool",
                           [pools + "."] + moved, by_pool)
        return Verdict(EXCLUSIVE, "Every attacker has a honeypot pool of their own",
                       [pools + "."] + moved, by_pool)

    findings = [f"Pool {n} is shared by {', '.join(labels)}." for n, labels in sorted(shared.items())]
    if sharing_justified(state):
        if state.get("capped"):
            reason = (f"pool growth is capped ({state.get('capped')}), so further attackers "
                      "were assigned to the ready pools round-robin")
        elif state.get("waiting"):
            reason = (f"{state.get('waiting')} session(s) were still waiting for the pool "
                      "pool_manager was building for them when the run ended")
        else:
            reason = ("no free pool was left, so new attackers were assigned to the "
                      "ready pools round-robin")
        return Verdict(SHARED_EXPECTED, "Pools are shared, as expected under resource pressure",
                       findings + [f"This is the designed fallback: {reason}."] + moved + cart_issues, by_pool)
    free = state.get("free", []) if state else []
    findings.append(
        "Sharing is only the designed fallback while pools are being built or once growth "
        "is capped, "
        + (f"but spare pool(s) {', '.join(map(str, free))} were free and growth is not capped."
           if free else "but the registry shows no reason for it (state unavailable or pools missing)."))
    return Verdict(SHARED_UNEXPECTED, "Pools are shared although free pools exist",
                   findings + moved + cart_issues, by_pool)
