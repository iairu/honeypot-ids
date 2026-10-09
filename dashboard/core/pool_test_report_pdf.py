"""Renders a core.pool_test_report.PoolTestData to a PDF: which honeypot pool
each test window's session landed in, and whether that matches the rule of
one malicious session per pool (shared only when pools run out).

GUI-thread only, same print machinery and Baskerville styling as
core/exploit_report_pdf.py."""
from __future__ import annotations

from PyQt6.QtCore import QMarginsF, QPointF, QRectF, QSizeF, Qt, QUrl
from PyQt6.QtGui import QFont, QFontMetrics, QPageLayout, QPageSize, QPainter, QPen, QPolygonF
from PyQt6.QtPrintSupport import QPrinter
from PyQt6.QtGui import QColor, QTextDocument

from core import diagrams, pool_evidence, vector_figures
from core.diagrams import _arrow, _box, _new
from core.exploit_report_pdf import (_FONT_CSS_STACK, _GREEN, _GREY, _ORANGE, _RED, _badge, _esc,
                                     _pool_state_html, _report_font_family)
from core.pool_test_report import (BORROWED, CART_LOST, EXCLUSIVE, INCOMPLETE, MERGED, OWN,
                                   PRODUCTION, SHARED, SHARED_EXPECTED, STATES, UNSTABLE,
                                   PoolTestData, ScalingSummary, Verdict, _quantile, analyze,
                                   CART_CHANGED, CART_CLEARED, CART_NONE, CART_RESTORED, CART_SAME,
                                   CART_UNREADABLE, cart_marks, cart_resets, load_stats, scaling_summary,
                                   usage_at)

_STATUS_COLOR = {EXCLUSIVE: _GREEN, SHARED_EXPECTED: _ORANGE, INCOMPLETE: _GREY, MERGED: _RED,
                 CART_LOST: _RED, UNSTABLE: _ORANGE}


def _short(session_id: str) -> str:
    return (session_id[:8] + "…") if session_id else "no session"


def routing_figure(data: PoolTestData, verdict: Verdict, family: str = "Serif"):
    """Window -> session -> pool, one arrow per window. A pool box that more
    than one window points at is drawn orange/red; unbound windows go to a
    grey 'no pool' box."""
    frames = data.frames
    pools = sorted({f.pool for f in frames if f.pool is not None})
    rows = max(len(frames), len(pools) + (1 if any(f.pool is None for f in frames) else 0))
    row_h = 84
    img, p = _new(820, 50 + rows * row_h)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor("#1a1a1a"))
    p.drawText(20, 24, "Each window's session and the honeypot pool it was given")

    owners = data.pool_state.get("owners", {}) if data.pool_state else {}
    targets: dict[int | None, tuple[float, float]] = {}
    slots = [*pools] + ([None] if any(f.pool is None for f in frames) else [])
    for i, n in enumerate(slots):
        targets[n] = (560, 48 + i * row_h)
    pool_h = 60
    for i, f in enumerate(frames):
        y = 48 + i * row_h
        tx, ty = targets[f.pool]
        shared = f.pool is not None and len(verdict.by_pool.get(f.pool, [])) > 1
        color = (_ORANGE if verdict.status == SHARED_EXPECTED else _RED) if shared \
            else (_GREY if f.pool is None else _GREEN)
        _arrow(p, 250, y + 30, tx, ty + pool_h / 2, color=color)
    for i, f in enumerate(frames):
        y = 48 + i * row_h
        _box(p, 20, y, 230, 60, f.label, f"session {_short(f.session_id)}",
             fill="#eef2f7", border="#1565c0", text="#1565c0", family=family)
    for n, (x, y) in targets.items():
        labels = verdict.by_pool.get(n, []) if n is not None else \
            [f.label for f in frames if f.pool is None]
        if n is None:
            _box(p, x, y, 240, pool_h, "No pool", ", ".join(labels),
                 fill="#f1f1f1", border=_GREY, text=_GREY, family=family)
            continue
        shared = len(labels) > 1
        color = (_ORANGE if verdict.status == SHARED_EXPECTED else _RED) if shared else _GREEN
        total = owners.get(n)
        sub = ", ".join(labels) + (f" • {total} owner(s) in Redis" if total is not None else "")
        _box(p, x, y, 240, pool_h, f"Honeypot pool {n}", sub,
             fill="#fdf1e0" if shared else "#e8f3ea", border=color, text=color, family=family)
    p.end()
    return img


def _frames_table(data: PoolTestData) -> str:
    rows = []
    for f in data.frames:
        pool = _badge(f"pool {f.pool}", _GREEN) if f.pool is not None else _badge("none", _GREY)
        rows.append(
            f'<tr><td><b>{_esc(f.label)}</b></td><td>{_esc(_short(f.session_id))}</td>'
            f'<td>{pool}</td><td>{_esc(f.language)}</td>'
            f'<td style="font-size:8pt;">{_esc(f.user_agent[-48:])}</td></tr>')
    return ('<table width="100%" cellspacing="0" cellpadding="4" border="1" '
            'style="border-collapse:collapse; color:#333;">'
            '<tr><th>Window</th><th>Session</th><th>Honeypot pool</th><th>Language</th>'
            '<th>User-Agent (tail)</th></tr>' + "".join(rows) + '</table>')


def _decision_cell(d) -> str:
    color = {"HONEYPOT": _ORANGE, "PRODUCTION": _GREEN}.get(d.route, _GREY)
    return (f'{_badge(d.route, color)}<br/><span style="font-size:8pt;">'
            f'{_esc("pool " + str(d.pool) if d.pool is not None else "no pool")}'
            f'{_esc(" \u2022 score " + str(d.score)) if d.score is not None else ""}</span>')


def _cart_cell(c) -> str:
    if c is None:
        return '<span style="color:#c62828;">cart unreadable</span>'
    if not c.items:
        return '<span style="color:#777;">cart empty</span>'
    lines = "<br/>".join(f"{_esc(n)} &times; {q}" for n, q in c.items)
    return f"<b>{_esc(c.total)}</b><br/>{lines}"


def _cart_section_html(data: PoolTestData) -> str:
    """Each window's cart across the run: filled on production, then it must be
    identical wherever the session is routed."""
    if not data.steps or not any(st.carts for st in data.steps):
        return ""
    marks, issues, notes = cart_marks(data.steps, cart_resets(data.cleared))
    cleared_before = {}
    for e in data.cleared:
        if e.clears_cookies():
            cleared_before.setdefault((e.step, e.window), e)
    badge = {CART_UNREADABLE: ("unreadable", _GREY), CART_NONE: ("no cart yet", _GREY),
             CART_CLEARED: ("empty since its cookies were cleared", _GREY),
             CART_RESTORED: ("cart back after clearing", _BLUE_INK),
             CART_SAME: ("same cart", _GREEN), CART_CHANGED: ("CART CHANGED", _RED)}
    rows = []
    for n, (step, row) in enumerate(zip(data.steps, marks)):
        cells = []
        for i, mark in enumerate(row):
            d = step.decisions[i] if i < len(step.decisions) else None
            where = (f"pool {d.pool}" if d is not None and d.pool is not None else "production")
            text, color = badge[mark]
            flag = ('<br/><span style="font-size:8pt;color:#1565c0;"><b>&#9670; cookies cleared '
                    'before this step</b></span>' if (n, i) in cleared_before else "")
            cells.append(f'<td>{_badge(text, color)}{flag}<br/>'
                         f'<span style="font-size:8pt;color:#555;">on {_esc(where)}</span></td>')
        rows.append(f'<tr><td>{_esc(step.title)}</td>{"".join(cells)}</tr>')
    head = "".join(f"<th>{_esc(f.label)}</th>" for f in data.frames)
    ok = ('Every cart stayed exactly as filled, on production and in every honeypot pool.'
          if not cleared_before else
          'Every cart stayed exactly as filled, on production and in every honeypot pool, until its '
          'window cleared its cookies; from then on it held only what the window had after clearing.')
    verdict = (f'<p style="color:#2e7d32;"><b>{ok}</b></p>' if not issues else
               '<ul style="color:#c62828;">' + "".join(f"<li>{_esc(x)}</li>" for x in issues) + "</ul>")
    if notes:
        verdict += ('<ul style="color:#555;">' + "".join(f"<li>{_esc(x)}</li>" for x in notes) + "</ul>")
    clearing = ('' if not cleared_before else
                '<p style="color:#555;">Where a window cleared its cookies (marked &#9670;), WooCommerce\'s '
                'cart cookie went with them, so the cart it filled is gone from the browser from that step '
                'on and an empty cart there is expected. If a cart shows up again after that, the browser '
                'did not bring it back: the stack restored it, and the report notes it below the table. '
                'That restored cart is then the one the later steps are compared with. Clearing only localStorage or '
                'sessionStorage leaves the cart cookie in place, so the cart must stay as it was.</p>')
    return ('<h2 style="color:#222;">Cart persistence</h2>'
            '<p style="color:#555;">A visitor diverted to a honeypot is served by a different database, so '
            'WooCommerce\'s own cart session does not exist there. The storefront therefore carries the '
            'cart in a cookie and rebuilds it on whichever instance serves the next request. Each window '
            'filled its cart on production; the cart was then read back after every step, through the same '
            'cookies and routing as the window\'s own traffic.</p>'
            + clearing +
            '<table width="100%" cellspacing="0" cellpadding="4" border="1" style="border-collapse:collapse;">'
            f'<tr><th>Step</th>{head}</tr>' + "".join(rows) + '</table>' + verdict)


def _steps_html(data: PoolTestData, doc: QTextDocument) -> str:
    """Per step: what each window did, the router's decision for its session
    afterwards, and a screenshot of each window at that moment."""
    if not data.steps:
        return ""
    out = ['<h2 style="color:#222;">Step by step</h2>',
           '<p style="color:#555;">All windows move in every step. An attacker\'s pool '
           'must appear in their own step, differ from the earlier ones, and never change '
           'afterwards &ndash; except once, from a pool it only borrowed while its own was '
           'being built to that new pool.</p>']
    shot_w = max(56, 615 // max(1, len(data.frames)))
    for n, step in enumerate(data.steps, start=1):
        head = "".join(f'<th>{_esc(f.label)}</th>' for f in data.frames)
        acts = "".join(f'<td style="font-size:8pt; color:#555;">{_esc(a)}</td>' for a in step.actions)
        decs = "".join(f'<td>{_decision_cell(d)}</td>' for d in step.decisions)
        carts = "".join(f'<td style="font-size:8pt;">{_cart_cell(c)}</td>' for c in step.carts) if step.carts else ""
        imgs = ""
        for i, shot in enumerate(step.shots):
            if shot is None or shot.isNull():
                imgs += "<td></td>"
                continue
            key = f"report://step{n}frame{i}"
            doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(key), shot)
            imgs += f'<td><img src="{key}" width="{shot_w}"/></td>'
        out.append(
            f'<h3 style="color:#222;">Step {n}: {_esc(step.title)}</h3>'
            f'<p style="color:#555;">{_esc(step.detail)}</p>'
            '<table width="100%" cellspacing="0" cellpadding="4" border="1" '
            'style="border-collapse:collapse;">'
            f'<tr>{head}</tr><tr>{acts}</tr><tr>{decs}</tr>' + (f'<tr>{carts}</tr>' if carts else '') + f'<tr>{imgs}</tr></table>')
    return "".join(out)


def _cleared_html(data: PoolTestData) -> str:
    """Every time a window cleared its own browser data, and what the stack did
    with it afterwards -- reported as observed, not judged."""
    if data.clear_seed is None:
        return ""
    intro = ('<h2 style="color:#222;">Windows clearing their browser data</h2>'
             '<p style="color:#555;">Between steps, random windows cleared their own data the way a '
             'regular visitor does from the browser\'s settings: every cookie of the site, its '
             'localStorage and sessionStorage, or both. Nothing was forged or rewritten. The table '
             'shows what each window had before, and the session and route the stack gave it once '
             'the next step settled. A window that lost its cookies also lost WooCommerce\'s cart '
             f'cookie, so its cart starts over there. Random seed: {data.clear_seed}.</p>')
    if not data.cleared:
        return intro + '<p style="color:#777;">No window cleared its data in this run.</p>'

    def where(pool, route):
        if pool is not None:
            return f"pool {pool}"
        return "production" if route in ("", "PRODUCTION") else route.lower()
    rows = []
    for e in data.cleared:
        label = data.frames[e.window].label if e.window < len(data.frames) else f"Window {e.window + 1}"
        step = data.steps[e.step].title if e.step < len(data.steps) else "?"
        before = f"{_short(e.before_session)}<br/>{_esc(where(e.before_pool, ''))}"
        if not e.resolved:
            after, badge = "&ndash;", _badge("not observed", _GREY)
        else:
            after = f"{_short(e.after_session)}<br/>{_esc(where(e.after_pool, e.after_route))}"
            badge = (_badge("same session", _BLUE_INK) if e.same_session()
                     else _badge("fresh session", _BLUE_INK) if e.after_session
                     else _badge("no session", _GREY))
        rows.append(
            f'<tr><td>{_mmss(e.t)}</td><td>{e.step + 1}: {_esc(step)}</td><td><b>{_esc(label)}</b></td>'
            f'<td>{_esc(e.what())}<br/><span style="font-size:8pt;color:#555;">{_esc(e.removed())}</span></td>'
            f'<td style="font-size:8pt;">{before}</td><td style="font-size:8pt;">{after}</td>'
            f'<td>{badge}<br/><span style="font-size:8pt;color:#555;">{_esc(e.outcome())}</span></td></tr>')
    same = sum(1 for e in data.cleared if e.resolved and e.same_session())
    fresh = sum(1 for e in data.cleared if e.resolved and e.after_session and not e.same_session())
    summary = (f'<p style="color:#555;">{len(data.cleared)} clearing(s): {same} kept their session, '
               f'{fresh} got a fresh one.</p>')
    return (intro + summary
            + '<table width="100%" cellspacing="0" cellpadding="4" border="1" '
            'style="border-collapse:collapse; color:#333;"><tr><th>Time</th><th>Before step</th>'
            '<th>Window</th><th>Cleared</th><th>Session before</th><th>Session after</th>'
            '<th>What the stack did</th></tr>' + "".join(rows) + '</table>')


def _runs_html(data: PoolTestData) -> str:
    if not data.runs:
        return ""
    rows = []
    for r in data.runs:
        result = (_badge(f"diverted after {r.attempts}", _GREEN) if r.diverted
                  else _badge(f"not diverted in {r.attempts}", _RED))
        note = " (replacement)" if r.replaced else ""
        rows.append(f'<tr><td><b>{_esc(r.window)}</b></td><td>{_esc(r.cve)}{note}</td>'
                    f'<td>{_esc(r.name)}</td><td>{result}</td>'
                    f'<td>{_esc("pool " + str(r.pool) if r.pool is not None else "none")}</td></tr>')
    return ('<h2 style="color:#222;">Exploits run per window</h2>'
            '<p style="color:#555;">Each window runs a different exploit, picked from the ones '
            'a live probe showed divert within three attempts. If a chosen exploit still did '
            'not divert in three attempts, the next candidate is used instead.</p>'
            '<table width="100%" cellspacing="0" cellpadding="4" border="1" '
            'style="border-collapse:collapse; color:#333;"><tr><th>Window</th><th>Exploit</th>'
            '<th>Name</th><th>Routing</th><th>Pool</th></tr>' + "".join(rows) + '</table>')


def _evidence_html(data: PoolTestData) -> str:
    if not data.evidence:
        return ""
    owner = {f.pool: f.label[-1] for f in data.frames if f.pool is not None}
    out = ['<h2 style="color:#222;">What each honeypot container saw and changed</h2>',
           '<p style="color:#555;">Read from each pool\'s own eshop and database containers '
           f'since the run started ({_esc(data.since or "unknown")}). Requests are matched to '
           'windows by their User-Agent tag, so a pool should show its owner\'s exploits and '
           'nobody else\'s. A pool no window owns is shown for contrast.</p>']
    for ev in sorted(data.evidence, key=lambda e: (e.pool not in owner, e.pool)):
        who = f"window {owner[ev.pool]}" if ev.pool in owner else "unowned spare"
        head = f'{_badge("pool " + str(ev.pool), _GREEN if ev.pool in owner else _GREY)} &nbsp;<b>{_esc(who)}</b>'
        if ev.error:
            out.append(f'<h3>{head}</h3><p style="color:#c62828;">{_esc(ev.error)}</p>')
            continue
        reqs = "".join(
            f'<li><b>{_esc(h.window)}</b> {_esc(h.method)} <span style="font-size:8pt;">'
            f'{_esc(h.path[:90])}</span> &rarr; {h.status}</li>' for h in ev.notable()) \
            or '<li style="color:#777;">none</li>'
        files = "".join(f'<li style="font-size:8pt;">{_esc(f)}</li>' for f in ev.files_changed[:10]) \
            or '<li style="color:#777;">no files written</li>'
        if ev.db_delta is None:
            db = '<span style="color:#777;">no baseline (pool built during the run)</span>'
        else:
            db = ", ".join(f"{k.replace('Com_', '').lower()} +{v}" for k, v in ev.db_delta.items())
        out.append(
            f'<h3 style="color:#222;">{head}</h3>'
            f'<table width="100%" cellspacing="0" cellpadding="4" border="1" '
            'style="border-collapse:collapse; color:#333;">'
            f'<tr><td width="22%"><b>Windows seen</b></td><td>{_esc(", ".join(ev.windows()) or "none")} '
            f'&nbsp;({len(ev.hits)} requests)</td></tr>'
            f'<tr><td><b>Requests received</b></td><td><ul>{reqs}</ul></td></tr>'
            f'<tr><td><b>Files changed</b></td><td><ul>{files}</ul></td></tr>'
            f'<tr><td><b>Database activity</b></td><td>{db}</td></tr></table>')
    return "".join(out)


def render_pdf(data: PoolTestData, out_path: str) -> Verdict:
    family = _report_font_family()
    verdict = analyze(data.frames, data.pool_state, data.steps, data.cleared)
    owners = {f.pool: f.label[-1] for f in data.frames if f.pool is not None}
    verdict.findings.extend(pool_evidence.cross_traffic(data.evidence, owners))
    summ = scaling_summary(data)
    first_delayed = len(data.frames) - data.delayed
    if data.delayed and summ.reserve.get("reached"):
        for c in summ.borrow:
            if c.window >= first_delayed:
                verdict.findings.append(
                    f"{data.frames[c.window].label} borrowed pool {c.borrowed} although "
                    "pools had been pre-built for the delayed windows.")
    for r in data.runs:
        if not r.diverted:
            verdict.findings.append(
                f"Window {r.window}: {r.cve} was not diverted within {r.attempts} attempts.")
    doc = QTextDocument()
    doc.setDefaultFont(QFont(family, 11))

    parts = [f'<div style="font-family: {_FONT_CSS_STACK};">',
             '<h1 style="color:#222;">Honeypot IDS &ndash; Pool test report</h1>',
             '<table width="100%" style="color:#555;"><tr><td>'
             f'Generated: {_esc(data.generated_at)}<br/>'
             f'Target: {_esc(data.target_label)} &nbsp; ({_esc(data.base_url)})<br/>'
             f'Exploits: {_esc(data.exploit)}<br/>'
             f'Windows: {len(data.frames)}<br/>'
             'Browser data cleared: ' + (f'{len(data.cleared)} time(s), in random windows'
                                         if data.clear_seed is not None else 'off')
             + '</td></tr></table><hr/>',
             '<h2 style="color:#222;">Result</h2>',
             f'<p>{_badge(verdict.status.replace("_", " ").upper(), _STATUS_COLOR.get(verdict.status, _RED))} '
             f'&nbsp;<b>{_esc(verdict.headline)}</b></p>',
             '<ul>' + "".join(f"<li>{_esc(x)}</li>" for x in verdict.findings) + '</ul>',
             '<h2 style="color:#222;">What is being tested</h2>',
             '<p style="color:#555;">Attackers are told apart by session, not by address. '
             'Each test window has its own cookie jar and its own User-Agent and language, so '
             f'the proxy sees {len(data.frames)} separate attackers. By default every malicious '
             'session is given a honeypot pool <b>of its own</b> (an eshop container with its own '
             'seeded database): the router hands a new attacker a free ready pool no other '
             'session owns, and the pools scale with the attacker sessions &ndash; a session '
             'that finds no free pool borrows one round-robin while pool_manager builds one for '
             'it, then moves there. Scaling stops at the configured resource limit '
             '(POOL_MAX_MEMORY_MB / POOL_MAX_CPUS / POOL_MAX) or when the host is short of '
             'memory, CPU or disk; from then on further attackers share the ready pools in '
             'strict round-robin order.</p>']
    parts.append(diagrams.figure_html(
        doc, routing_figure(data, verdict, family), "pool-routing", 1,
        "One arrow per test window, from its session to the honeypot pool the router bound "
        "it to. Green: the pool belongs to that window alone. Orange: shared under resource "
        "pressure (designed). Red: shared or merged without a reason. Grey: not bound.",
        width=640))
    parts.append('<h2 style="color:#222;">Windows</h2>')
    parts.append(_frames_table(data))
    parts.append(_cleared_html(data))
    scaling, _next_fig = _scaling_html(data, doc, family, 2)
    parts.append(scaling)
    parts.append(_round_robin_html(data))
    parts.append(_scaledown_html(data))
    parts.append(_cart_section_html(data))
    parts.append(_runs_html(data))
    parts.append(_steps_html(data, doc))
    parts.append(_evidence_html(data))
    parts.append('<h2 style="color:#222;">Pool registry at export time</h2>')
    parts.append(_pool_state_html(data.pool_state))

    shots = [f for f in data.frames if f.screenshot is not None and not f.screenshot.isNull()
             and not data.steps]
    if shots:
        parts.append('<h2 style="color:#222;">What each window showed</h2>')
        for i, f in enumerate(shots):
            doc.addResource(QTextDocument.ResourceType.ImageResource,
                            QUrl(f"report://frame{i}"), f.screenshot)
            pool = f"pool {f.pool}" if f.pool is not None else "no pool"
            parts.append(f'<p><b>{_esc(f.label)}</b> ({pool}) &ndash; {_esc(f.url)}<br/>'
                         f'<img src="report://frame{i}" width="640"/></p>')
    parts.append('</div>')
    doc.setHtml("<body>" + "".join(parts) + "</body>")
    vector_figures.embed_figures(doc)

    printer = QPrinter(QPrinter.PrinterMode.ScreenResolution)
    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
    printer.setOutputFileName(out_path)
    printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    printer.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Unit.Millimeter)
    doc.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.DevicePixel).size()))
    doc.print(printer)
    return verdict


# ---- scaling and latency ---------------------------------------------------

_STATE_FILL = {PRODUCTION: "#cfd4da", OWN: _GREEN, BORROWED: _ORANGE, SHARED: _RED}
_STATE_INK = {PRODUCTION: "#1a1a1a", OWN: "#ffffff", BORROWED: "#1a1a1a", SHARED: "#ffffff"}
_STATE_LABEL = {PRODUCTION: "production", OWN: "own pool", BORROWED: "borrowed (not scaled yet)",
                SHARED: "shared (resource limit)"}
# Build phases are ordered stages: one hue, dark (first) to light (last).
_PHASE_RAMP = ["#0d47a1", "#1565c0", "#1e88e5", "#42a5f5", "#90caf9", "#bbdefb"]
_PURPLE = "#6a3fb0"
_INK = "#1a1a1a"
_MUTED = "#666666"


def _mmss(t: float) -> str:
    t = max(0, int(round(t)))
    return f"{t // 60}:{t % 60:02d}"


def _tick_step(span: float, max_ticks: int = 10) -> float:
    for step in (5, 10, 15, 30, 60, 120, 300, 600, 1200):
        if span / step <= max_ticks:
            return step
    return 1800


def _phase_names(builds) -> list[str]:
    names: list[str] = []
    for b in builds:
        for name, _sec in b.phases:
            if name not in names:
                names.append(name)
    return names


def _phase_color(names: list[str], name: str) -> str:
    i = names.index(name) if name in names else len(names)
    return _PHASE_RAMP[min(i, len(_PHASE_RAMP) - 1)]


def _legend(p: QPainter | None, x: float, y: float, items: list[tuple[str, str]], family: str,
            width: float) -> float:
    """Swatch + label pairs, wrapping at `width`; returns the y below them.
    With p=None it only measures."""
    font = QFont(family, 9)
    fm = QFontMetrics(font)
    if p is not None:
        p.setFont(font)
    cx = x
    for color, label in items:
        w = 16 + fm.horizontalAdvance(label) + 18
        if cx + w > x + width:
            cx, y = x, y + fm.height() + 6
        if p is None:
            cx += w
            continue
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(color))
        p.drawRoundedRect(QRectF(cx, y + 2, 12, 12), 2, 2)
        p.setPen(QColor(_INK))
        p.drawText(QPointF(cx + 16, y + 12), label)
        cx += w
    return y + fm.height() + 6


def _time_axis(p: QPainter, x0: float, x1: float, y: float, span: float, family: str,
               grid_top: float | None = None) -> None:
    font = QFont(family, 8)
    p.setFont(font)
    step = _tick_step(span)
    t = 0.0
    while t <= span + 1e-6:
        x = x0 + (t / span) * (x1 - x0)
        if grid_top is not None:
            p.setPen(QPen(QColor("#e6e6e6"), 1))
            p.drawLine(QPointF(x, grid_top), QPointF(x, y))
        p.setPen(QPen(QColor("#999999"), 1))
        p.drawLine(QPointF(x, y), QPointF(x, y + 4))
        p.setPen(QColor(_MUTED))
        label = _mmss(t)
        p.drawText(QPointF(x - QFontMetrics(font).horizontalAdvance(label) / 2, y + 16), label)
        t += step
    p.setPen(QPen(QColor("#999999"), 1))
    p.drawLine(QPointF(x0, y), QPointF(x1, y))


def _bar(p: QPainter, x0: float, x1: float, y: float, h: float, color: str,
         outline: str | None = None, dashed: bool = False) -> None:
    """A segment with a 1px surface gap on each side so neighbours stay apart."""
    r = QRectF(x0 + 1, y, max(1.0, x1 - x0 - 2), h)
    p.setBrush(QColor(color))
    if outline:
        pen = QPen(QColor(outline), 1.5)
        if dashed:
            pen.setStyle(Qt.PenStyle.DashLine)
        p.setPen(pen)
    else:
        p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(r, 3, 3)


def _text_in(p: QPainter, x0: float, x1: float, y: float, h: float, text: str, ink: str,
             family: str) -> None:
    font = QFont(family, 8)
    fm = QFontMetrics(font)
    if fm.horizontalAdvance(text) + 6 > x1 - x0:
        return
    p.setFont(font)
    p.setPen(QColor(ink))
    p.drawText(QRectF(x0, y, x1 - x0, h), int(Qt.AlignmentFlag.AlignCenter), text)


def scaling_timeline_figure(data: PoolTestData, summ: ScalingSummary, family: str = "Serif"):
    """Gantt of the whole run: where each window was served over time, every
    pool built during it (phases shaded), hand-offs from a finished build to
    the window that got it, and when the resource limit / pre-build happened."""
    builds = summ.builds
    removals = summ.removals
    span = max([data.duration, 1.0] + [b.start + (b.seconds or 0) for b in builds]
               + [r.at for r in removals])
    W, ml, mr = 900, 150, 24
    plot_w = W - ml - mr
    row_h, bar_h = 26, 18
    windows = sorted(summ.timelines)
    font = QFont(family, 9)
    fm = QFontMetrics(font)

    def X(t):
        return ml + (max(0.0, min(t, span)) / span) * plot_w

    # Marker band: step numbers, then labelled events, each on a free row.
    markers = []   # (x, label, color, dashed)
    for t, reason in summ.capped:
        markers.append((X(t), "resource limit reached", _RED, True))
    if summ.reserve.get("requested"):
        r = summ.reserve
        markers.append((X(r["start"]), f"pre-build of {r['requested']} pool(s) requested",
                        _PURPLE, True))
        if r.get("end") is not None:
            markers.append((X(r["end"]), f"{r['requested']} pool(s) ready" if r.get("reached")
                            else "pre-build stopped", _PURPLE, False))
    sd = data.scaledown or {}
    if sd.get("requested") is not None:
        markers.append((X(sd["requested"]), "scale-down requested", _INK, True))
        if sd.get("done") is not None:
            markers.append((X(sd["done"]), "scale-down done", _INK, False))
    rows_end: list[float] = []
    placed = []
    for m in markers:
        w = fm.horizontalAdvance(m[1]) + 6
        left = m[0] + 3 if m[0] + 3 + w <= W - 2 else m[0] - 3 - w
        row = next((i for i, end in enumerate(rows_end) if left > end + 4), None)
        if row is None:
            rows_end.append(left + w)
            row = len(rows_end) - 1
        else:
            rows_end[row] = left + w
        placed.append((left, row, m))
    title_h, step_h = 28, 18
    band = title_h + step_h + len(rows_end) * (fm.height() + 2) + 6
    win_top = band
    build_top = win_top + len(windows) * row_h + (28 if builds or removals else 0)
    plot_bottom = build_top + (len(builds) + len(removals)) * row_h + 6
    names = _phase_names(builds)
    items = [(_STATE_FILL[s], _STATE_LABEL[s]) for s in STATES]
    items += [(_phase_color(names, n), f"build: {n}") for n in names]
    if builds:
        items.append(("#b0bec5", "build: create / register"))
    if removals:
        items.append((_REMOVED, "pool removed (scale-down)"))
    if data.cleared:
        items.append((_INK, "window cleared its browser data (diamond)"))
    H = int(_legend(None, ml, plot_bottom + 24, items, family, plot_w)) + 8

    img, p = vector_figures.new_figure(W, H)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 20, "Pool scaling over the run")
    _time_axis(p, ml, ml + plot_w, plot_bottom, span, family, grid_top=win_top - 4)

    # Step ticks (numbers match the "Step by step" section).
    p.setFont(QFont(family, 8))
    for i, (t, _title) in enumerate(data.marks, start=1):
        x = X(t)
        p.setPen(QPen(QColor("#bdbdbd"), 1, Qt.PenStyle.DotLine))
        p.drawLine(QPointF(x, title_h + step_h - 2), QPointF(x, plot_bottom))
        p.setPen(QColor(_MUTED))
        p.drawText(QPointF(x - 3, title_h + 10), str(i))
    for left, row, (x, label, color, dashed) in placed:
        y = title_h + step_h + row * (fm.height() + 2)
        pen = QPen(QColor(color), 1.5)
        if dashed:
            pen.setStyle(Qt.PenStyle.DashLine)
        p.setPen(pen)
        p.drawLine(QPointF(x, y + 2), QPointF(x, plot_bottom))
        p.setFont(font)
        p.setPen(QColor(color))
        p.drawText(QPointF(left, y + fm.ascent()), label)

    # Window rows.
    p.setFont(font)
    row_y = {}
    for k, w in enumerate(windows):
        y = win_top + k * row_h
        row_y[w] = y
        p.setPen(QColor(_INK))
        label = data.frames[w].label if w < len(data.frames) else f"Window {w + 1}"
        if w >= len(data.frames) - data.delayed:
            label += " (delayed)"
        p.drawText(QRectF(8, y, ml - 14, bar_h), int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter), label)
        for t0, t1, state, pool in summ.timelines[w]:
            _bar(p, X(t0), X(t1), y, bar_h, _STATE_FILL[state])
            if pool is not None:
                _text_in(p, X(t0), X(t1), y, bar_h, f"pool {pool}", _STATE_INK[state], family)
        for e in data.cleared:
            if e.window == w:   # a small black diamond where the window cleared its data
                x = X(e.t)
                p.setPen(QPen(QColor("#ffffff"), 1))
                p.setBrush(QColor(_INK))
                p.drawPolygon(QPolygonF([QPointF(x, y - 2), QPointF(x + 5, y + bar_h / 2),
                                         QPointF(x, y + bar_h + 2), QPointF(x - 5, y + bar_h / 2)]))
                p.setBrush(Qt.BrushStyle.NoBrush)

    # Build rows.
    if builds or removals:
        p.setFont(QFont(family, 9, QFont.Weight.Bold))
        p.setPen(QColor(_INK))
        p.drawText(QPointF(8, build_top - 10), "Pools built" + (" / removed" if removals else ""))
    for k, rm in enumerate(removals):
        y = build_top + (len(builds) + k) * row_h
        p.setFont(font)
        p.setPen(QColor(_INK))
        p.drawText(QRectF(8, y, ml - 14, bar_h), int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                   f"pool {rm.pool}")
        x0, x1 = X(rm.at - rm.seconds), X(rm.at)
        _bar(p, x0, max(x1, x0 + 4), y, bar_h, _REMOVED)
        label = f"removed in {rm.seconds:.1f} s \u00b7 " + ("forced" if rm.forced else
                                                             f"idle {rm.idle:.0f} s" if rm.idle else "idle")
        lx = max(x1, x0 + 4) + 4
        if lx + fm.horizontalAdvance(label) > W - 2:
            lx = x0 - 4 - fm.horizontalAdvance(label)
        p.drawText(QPointF(lx, y + bar_h - 5), label)
    by_pool_end = {}
    for k, b in enumerate(builds):
        y = build_top + k * row_h
        p.setFont(font)
        p.setPen(QColor(_INK))
        p.drawText(QRectF(8, y, ml - 14, bar_h), int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                   f"pool {b.pool}")
        end = b.start + (b.seconds if b.seconds is not None else span - b.start)
        if b.seconds is None:
            _bar(p, X(b.start), X(end), y, bar_h, "#e3eaf3", outline=_BLUE_INK, dashed=True)
            _text_in(p, X(b.start), X(end), y, bar_h, "still building", _INK, family)
            continue
        t = b.start
        for name, sec in b.phases:
            _bar(p, X(t), X(t + sec), y, bar_h, _phase_color(names, name))
            t += sec
        if end > t:   # container creation, network attach, registration
            _bar(p, X(t), X(end), y, bar_h, "#b0bec5")
        if not b.ok:
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(QColor(_RED), 2))
            p.drawRoundedRect(QRectF(X(b.start), y, X(end) - X(b.start), bar_h), 3, 3)
        label = f"{b.seconds:.0f} s" + ("" if b.ok else " FAILED") + (f" \u00b7 {b.reason}" if b.reason else "")
        lx = X(end) + 4
        if lx + fm.horizontalAdvance(label) > W - 2:
            lx = X(b.start) - 4 - fm.horizontalAdvance(label)
        p.setPen(QColor(_INK))
        p.drawText(QPointF(lx, y + bar_h - 5), label)
        by_pool_end.setdefault(b.pool, []).append((end, y))

    # Hand-offs: from the finished build to the window row that got the pool.
    sid_win = {}
    for smp in data.samples:
        if smp.session_id:
            sid_win[smp.session_id] = smp.window
    for e in data.events:
        if e.get("type") != "handoff":
            continue
        w = sid_win.get(str(e.get("session")))
        ends = by_pool_end.get(e.get("pool"))
        if w is None or w not in row_y or not ends:
            continue
        end, by = min(ends, key=lambda v: abs(v[0] - e["at"]))
        _arrow(p, X(end), by, X(e["at"]), row_y[w] + bar_h, color=_GREY, dashed=True, width=1)

    _legend(p, ml, plot_bottom + 24, items, family, plot_w)
    p.end()
    return img


_BLUE_INK = "#1565c0"
_REMOVED = "#6d4c41"


def usage_figure(data: PoolTestData, summ: ScalingSummary, family: str = "Serif"):
    """Small multiples on one time axis: memory, CPU and running pools of all
    honeypot pool containers, with the build ends, the resource limit and the
    scale-down marked. Separate panels, so each keeps its own honest scale."""
    usage = sorted(data.usage, key=lambda u: u.t)
    span = max([data.duration, 1.0] + [u.t for u in usage])
    W, ml, mr = 900, 110, 24
    plot_w = W - ml - mr
    panels = [("Memory in use", lambda u: u.mem_mb, "MB", _BLUE_INK),
              ("CPU in use", lambda u: u.cpu_percent, "% of one CPU", _BLUE_INK),
              ("Pools running", lambda u: float(u.pools), "pools", _BLUE_INK)]
    panel_h, gap, top = 110, 30, 56
    H = top + len(panels) * (panel_h + gap) + 34
    img, p = vector_figures.new_figure(W, H)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 20, "Honeypot pool containers: resource use over the run")
    font = QFont(family, 8)

    def X(t):
        return ml + (max(0.0, min(t, span)) / span) * plot_w
    events = [(b.start + b.seconds, _GREEN) for b in summ.builds if b.seconds is not None and b.ok]
    events += [(t, _RED) for t, _r in summ.capped]
    events += [(r.at, _REMOVED) for r in summ.removals]
    sd = data.scaledown or {}
    for k, (title, value, unit, color) in enumerate(panels):
        y0 = top + k * (panel_h + gap)
        vals = [value(u) for u in usage]
        vmax = max(vals + [1.0]) * 1.15
        p.setFont(QFont(family, 9, QFont.Weight.Bold))
        p.setPen(QColor(_INK))
        p.drawText(QPointF(ml, y0 - 4), f"{title} ({unit})")
        p.setFont(font)
        for frac in (0.0, 0.5, 1.0):
            y = y0 + panel_h - frac * panel_h
            p.setPen(QPen(QColor("#e6e6e6"), 1))
            p.drawLine(QPointF(ml, y), QPointF(ml + plot_w, y))
            p.setPen(QColor(_MUTED))
            lab = f"{vmax * frac:,.0f}"
            p.drawText(QRectF(0, y - 8, ml - 8, 16), int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter), lab)
        if sd.get("requested") is not None:
            x0 = X(sd["requested"])
            x1 = X(sd["done"] if sd.get("done") is not None else span)
            p.fillRect(QRectF(x0, y0, max(2.0, x1 - x0), panel_h), QColor("#efebe9"))
        for t, c in events:
            p.setPen(QPen(QColor(c), 1, Qt.PenStyle.DashLine))
            p.drawLine(QPointF(X(t), y0), QPointF(X(t), y0 + panel_h))
        if len(usage) >= 2:
            pen = QPen(QColor(color), 2)
            p.setPen(pen)
            pts = [QPointF(X(u.t), y0 + panel_h - (value(u) / vmax) * panel_h) for u in usage]
            for a, b in zip(pts, pts[1:]):
                p.drawLine(a, b)
            p.setBrush(QColor(color))
            p.setPen(Qt.PenStyle.NoPen)
            for pt in (pts[0], pts[-1]):
                p.drawEllipse(pt, 3, 3)
        elif not usage:
            p.setPen(QColor(_MUTED))
            p.drawText(QRectF(ml, y0, plot_w, panel_h), int(Qt.AlignmentFlag.AlignCenter),
                       "no resource samples (docker stats unavailable)")
    _time_axis(p, ml, ml + plot_w, top + len(panels) * (panel_h + gap) - gap, span, family)
    p.end()
    return img


def _hbar_chart(rows: list[tuple[str, float, str, str]], unit: str, title: str,
                family: str, whiskers: dict | None = None):
    """Horizontal bars on one value axis: (label, value, color, note). Optional
    whiskers {row index: (p90, max)} draw a thin line to the p90 and a tick at
    the max."""
    font = QFont(family, 9)
    fm = QFontMetrics(font)
    W, ml = 900, 210
    mr = 12 + max([fm.horizontalAdvance(n) for _l, _v, _c, n in rows] + [40])
    plot_w = max(240, W - ml - mr)
    W = ml + plot_w + mr
    row_h, bar_h = 26, 16
    vmax = max([v for _l, v, _c, _n in rows] + [m for _p, m in (whiskers or {}).values()] + [1.0])
    step = None
    for s in (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000):
        if vmax / s <= 8:
            step = s
            break
    step = step or 10000
    vmax = step * (int(vmax / step) + 1)
    top = 34
    H = top + len(rows) * row_h + 34
    img, p = vector_figures.new_figure(W, H)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 20, title)

    def X(v):
        return ml + (v / vmax) * plot_w
    base = top + len(rows) * row_h
    p.setFont(QFont(family, 8))
    v = 0
    while v <= vmax:
        x = X(v)
        p.setPen(QPen(QColor("#e6e6e6"), 1))
        p.drawLine(QPointF(x, top - 4), QPointF(x, base))
        p.setPen(QColor(_MUTED))
        lab = f"{v:g} {unit}"
        p.drawText(QPointF(x - QFontMetrics(p.font()).horizontalAdvance(lab) / 2, base + 16), lab)
        v += step
    for i, (label, value, color, note) in enumerate(rows):
        y = top + i * row_h
        p.setFont(font)
        p.setPen(QColor(_INK))
        p.drawText(QRectF(8, y, ml - 14, bar_h), int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter), label)
        _bar(p, ml - 1, X(value) + 1, y, bar_h, color)
        end = X(value)
        if whiskers and i in whiskers:
            p90, mx = whiskers[i]
            p.setPen(QPen(QColor(_INK), 1.2))
            p.drawLine(QPointF(X(value), y + bar_h / 2), QPointF(X(mx), y + bar_h / 2))
            p.drawLine(QPointF(X(p90), y + 3), QPointF(X(p90), y + bar_h - 3))
            p.drawLine(QPointF(X(mx), y + 1), QPointF(X(mx), y + bar_h - 1))
            end = X(mx)
        p.setPen(QColor(_INK))
        p.drawText(QPointF(end + 6, y + bar_h - 4), note)
    p.setPen(QPen(QColor("#999999"), 1))
    p.drawLine(QPointF(ml, base), QPointF(ml + plot_w, base))
    p.end()
    return img


def build_breakdown_figure(summ: ScalingSummary, family: str = "Serif"):
    """Per pool built: its build time split into phases (stacked)."""
    builds = [b for b in summ.builds if b.seconds is not None]
    names = _phase_names(builds)
    W, ml, mr = 900, 210, 90
    plot_w = W - ml - mr
    row_h, bar_h = 26, 16
    vmax = max([b.seconds for b in builds] + [1.0])
    step = _tick_step(vmax, 8)
    vmax = step * (int(vmax / step) + 1)
    top = 34
    base = top + len(builds) * row_h
    items = [(_phase_color(names, n), n) for n in names] + [("#b0bec5", "create / register")]
    H = int(_legend(None, ml, base + 26, items, family, plot_w)) + 8
    img, p = vector_figures.new_figure(W, H)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    font = QFont(family, 9)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 20, "Time to add one honeypot pool, by phase")

    def X(v):
        return ml + (v / vmax) * plot_w
    _time_axis(p, ml, ml + plot_w, base, vmax, family, grid_top=top - 4)
    for i, b in enumerate(builds):
        y = top + i * row_h
        p.setFont(font)
        p.setPen(QColor(_INK))
        p.drawText(QRectF(8, y, ml - 14, bar_h), int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                   f"pool {b.pool} ({b.reason or 'build'})")
        t = 0.0
        for name, sec in b.phases:
            _bar(p, X(t), X(t + sec), y, bar_h, _phase_color(names, name))
            t += sec
        if b.seconds > t:
            _bar(p, X(t), X(b.seconds), y, bar_h, "#b0bec5")
        p.setPen(QColor(_RED if not b.ok else _INK))
        p.drawText(QPointF(X(b.seconds) + 6, y + bar_h - 4),
                   f"{b.seconds:.0f} s" + ("" if b.ok else " FAILED"))
    _legend(p, ml, base + 26, items, family, plot_w)
    p.end()
    return img


def _ms(v: float) -> str:
    return f"{v / 1000:.2f} s" if v >= 1000 else f"{v:.0f} ms"


def _secs(v) -> str:
    return "—" if v is None else f"{v:.0f} s"


def _scaling_html(data: PoolTestData, doc: QTextDocument, family: str, fig: int) -> tuple[str, int]:
    """Section: how fast pools were added, how long windows borrowed a pool,
    and page-load latency per routing state. Returns (html, next figure no)."""
    summ = scaling_summary(data)
    status = (data.pool_state or {}).get("status") or {}
    builds_done = [b for b in summ.builds if b.seconds is not None]
    ok = [b.seconds for b in builds_done if b.ok]
    waits = [c.end - c.start for c in summ.borrow if c.end is not None and c.outcome == "own"]
    res = summ.reserve
    out = ['<h2 style="color:#222;">Scaling and latency</h2>',
           '<p style="color:#555;">pool_manager adds one honeypot pool (an eshop container plus '
           'its own database seeded from production) for every attacker session that finds no '
           'free pool, up to the resource limit. These figures come from pool_manager\'s own '
           'event log (build phases, hand-overs with their wait time, resource-limit changes) '
           'and from the windows themselves (routing read after every step and every 2 s while '
           'waiting; the duration of each page load).</p>']
    rows = [("Windows", f"{len(data.frames)}" + (f", of which {data.delayed} attacked only after "
                                                 "pools were pre-built for them" if data.delayed else "")),
            ("Run time", _mmss(data.duration))]
    if status:
        lim = []
        if status.get("max_memory_mb"):
            lim.append(f"{status['max_memory_mb']:g} MB")
        if status.get("max_cpus"):
            lim.append(f"{status['max_cpus']:g} CPUs")
        lim.append(f"POOL_MAX {status.get('max_pools')}")
        rows.append(("Resource limit", ", ".join(lim) + f" (a pool reserves "
                     f"{status.get('mem_per_pool')} MB / {status.get('cpus_per_pool'):g} CPUs); "
                     f"{status.get('pools')} pool(s) exist, room for {status.get('room')} more"))
    else:
        rows.append(("Resource limit", "unknown (pool_manager status not readable)"))
    rows.append(("Pools added during the run",
                 f"{len(ok)} built" + (f", {len(builds_done) - len(ok)} failed" if len(builds_done) > len(ok) else "")
                 + (f", {len(summ.builds) - len(builds_done)} still building" if len(summ.builds) > len(builds_done) else "")
                 + (f"; build time median {_quantile(ok, .5):.0f} s, max {max(ok):.0f} s" if ok else "")))
    rows.append(("Round-robin while not scaled yet (case A)",
                 f"{len(summ.borrow)} window(s) borrowed a pool"
                 + (f"; moved to their own after median {_quantile(waits, .5):.0f} s, max {max(waits):.0f} s"
                    if waits else "")))
    rows.append(("Round-robin at the resource limit (case B)",
                 f"{len(summ.limit)} window(s) share a pool for good"
                 + (f"; limit first reached at {_mmss(summ.capped[0][0])} ({summ.capped[0][1]})"
                    if summ.capped else "")))
    sd = data.scaledown or {}
    if sd.get("requested") is not None:
        rows.append(("Forced scale-down at the end",
                     f"{_pools_before_count(sd)} \u2192 {len(sd.get('pools_after', []))} pool(s) "
                     + (f"in {sd['done'] - sd['requested']:.0f} s" if sd.get("done") is not None
                        else f"(not finished after {SCALEDOWN_TIMEOUT_TEXT})")))
    if res.get("requested"):
        took = (res.get("end") or data.duration) - res["start"]
        rows.append(("Pre-build for the delayed windows",
                     f"{res['requested']} pool(s) ready after {took:.0f} s" if res.get("reached")
                     else f"{res.get('free', 0)} of {res['requested']} ready after {took:.0f} s "
                          f"({res.get('reason') or 'stopped'})"))
    out.append('<table width="100%" cellspacing="0" cellpadding="4" border="1" '
               'style="border-collapse:collapse; color:#333;">'
               + "".join(f'<tr><td width="32%"><b>{_esc(k)}</b></td><td>{_esc(v)}</td></tr>' for k, v in rows)
               + '</table><br/>')

    out.append(diagrams.figure_html(
        doc, scaling_timeline_figure(data, summ, family), "pool-scaling-timeline", fig,
        "Where each window was served over the run (grey: production, green: its own pool, "
        "orange: a borrowed pool while its own was being built, red: shared because the "
        "resource limit was reached), and every pool built during the run, its phases shaded "
        "dark to light. Dashed grey arrows: a finished pool handed to the window that waited "
        "for it. Numbered dotted lines: the steps below."
        + (" Black diamonds: a window cleared its browser data." if data.cleared else ""),
        width=640))
    fig += 1
    if builds_done:
        out.append(diagrams.figure_html(
            doc, build_breakdown_figure(summ, family), "pool-build-breakdown", fig,
            "Latency of adding one honeypot pool: wall time from the decision to build it until "
            "it was registered healthy, split into pool_manager's phases.", width=640))
        fig += 1
        out.append('<table width="100%" cellspacing="0" cellpadding="4" border="1" '
                   'style="border-collapse:collapse; color:#333; font-size:9pt;"><tr><th>Pool</th>'
                   '<th>Built for</th><th>Started</th><th>Build time</th><th>Phases</th></tr>'
                   + "".join(
                       f'<tr><td>{b.pool}</td><td>{_esc(b.reason or "-")}</td><td>{_mmss(b.start)}</td>'
                       f'<td>{_secs(b.seconds)}{"" if b.ok else " &ndash; failed: " + _esc(b.error[:120])}</td>'
                       f'<td>{_esc(", ".join(f"{n} {s:.0f} s" for n, s in b.phases) or "-")}</td></tr>'
                       for b in summ.builds) + '</table><br/>')
    elif not summ.builds:
        out.append('<p style="color:#555;">No pool was built during the run: the ready pools '
                   'covered every window, or growth was capped from the start.</p>')

    wait_rows, frames = [], data.frames
    for c in summ.borrow:
        label = frames[c.window].label if c.window < len(frames) else f"Window {c.window + 1}"
        if c.end is None:
            wait_rows.append((label, data.duration - c.start, _ORANGE,
                              f"still borrowing pool {c.borrowed} at the end"))
            continue
        note = (f"pool {c.borrowed} → own pool {c.own_pool}" if c.outcome == "own"
                else f"pool {c.borrowed}, then shared at the limit")
        if c.waited is not None:
            note += f" (manager: {c.waited:.0f} s)"
        wait_rows.append((label, c.end - c.start, _ORANGE if c.outcome == "own" else _RED, note))
    if res.get("requested"):
        took = (res.get("end") or data.duration) - res["start"]
        wait_rows.append((f"pre-build of {res['requested']} pool(s)", took, _PURPLE,
                          "ready" if res.get("reached") else (res.get("reason") or "stopped")))
    if wait_rows:
        out.append(diagrams.figure_html(
            doc, _hbar_chart(wait_rows, "s", "How long windows waited for a pool of their own", family),
            "pool-wait-latency", fig,
            "Orange: time a window spent on a borrowed pool (assigned round-robin because no pool "
            "was free yet) until it was moved to the pool built for it, as seen by the window "
            "(2 s resolution); pool_manager's own measurement in brackets. Red: the window was "
            "left on the borrowed pool because the resource limit was reached. Purple: time to "
            "pre-build the pools for the delayed windows.", width=640))
        fig += 1

    if data.usage:
        out.append(diagrams.figure_html(
            doc, usage_figure(data, summ, family), "pool-usage", fig,
            "Memory, CPU and number of running honeypot pools (eshop + database containers, "
            "docker stats every 10 s, every 3 s around the scale-down). Dashed lines: green a pool "
            "finished building, red the resource limit was reached, brown a pool was removed. "
            "Shaded: the forced scale-down at the end of the run.", width=640))
        fig += 1

    stats = load_stats(data.loads)
    if stats:
        rows_l, whisk = [], {}
        for i, st in enumerate(s for s in STATES if s in stats):
            v = stats[st]
            rows_l.append((_STATE_LABEL[st], v["median"], _STATE_FILL[st],
                           f"{_ms(v['median'])} \u00b7 p90 {_ms(v['p90'])} \u00b7 max {_ms(v['max'])} \u00b7 n={v['n']}"))
            whisk[i] = (v["p90"], v["max"])
        out.append(diagrams.figure_html(
            doc, _hbar_chart(rows_l, "ms", "Page load latency by where the window was served",
                             family, whisk),
            "pool-load-latency", fig,
            "Every page load of every window during the run (browser navigation start to load "
            "finished), grouped by where that window was routed right after it. Bar: median; "
            "short tick: 90th percentile; line end: slowest load.", width=640))
        fig += 1
    return "".join(out), fig


SCALEDOWN_TIMEOUT_TEXT = "5 min"


def _building_before(sd: dict) -> list[int]:
    """Pools still being built when the forced scale-down was requested:
    pool_manager waits for them and removes them too if they are not needed."""
    return [n for n in sd.get("building_before", []) if n not in sd.get("pools_before", [])]


def _pools_before_count(sd: dict) -> int:
    return len(sd.get("pools_before", [])) + len(_building_before(sd))


def _scaledown_html(data: PoolTestData) -> str:
    """Section: how pools are scaled down when idle, and what the forced
    scale-down at the end of this run freed and how long it took."""
    summ = scaling_summary(data)
    sd = data.scaledown or {}
    status = (data.pool_state or {}).get("status") or {}
    timeout = sd.get("idle_timeout", status.get("idle_timeout"))
    if timeout is None:
        rule = "The idle timeout is unknown (pool_manager status not readable)."
    elif not timeout:
        rule = ("POOL_IDLE_TIMEOUT_SECONDS is 0: pools are never scaled down for being idle "
                "(only on request, as below).")
    else:
        rule = (f"pool_manager scales down a pool once no request has reached it for "
                f"POOL_IDLE_TIMEOUT_SECONDS = {timeout:g} s ({_mmss(timeout)}): its attackers' "
                "assignments are dropped (a returning attacker is assigned afresh) and pools above "
                f"the spare count ({sd.get('spares', status.get('spares', '?'))}) are removed with "
                "their volumes, "
                "freeing what they reserved. Compose-declared pools are only freed, never removed.")
    out = ['<h2 style="color:#222;">Scale-down</h2>',
           f'<p style="color:#555;">{_esc(rule)} Waiting that long is not practical in a test, so '
           'the run ends by forcing it: the windows stop sending requests, their sessions are '
           'released, and pool_manager removes the pools that are no longer needed at once. Other '
           'sessions\' pools are not touched.</p>']
    if sd.get("requested") is None:
        out.append('<p style="color:#555;">The forced scale-down did not run.</p>')
        return "".join(out)
    before = usage_at(data.usage, sd["requested"])
    after = usage_at(data.usage, (sd.get("done") or data.duration) + 2, after=True) or \
        usage_at(data.usage, data.duration)
    removed = [r for r in summ.removals if r.at >= sd["requested"] - 1]
    per = sd.get("mem_per_pool")
    building = _building_before(sd)
    nb, na = _pools_before_count(sd), len(sd.get("pools_after", []))
    rows = [("Requested at", _mmss(sd["requested"])),
            ("Sessions released", str(sd.get("sessions", 0))),
            ("Finished", f"after {sd['done'] - sd['requested']:.1f} s" if sd.get("done") is not None
             else f"not within {SCALEDOWN_TIMEOUT_TEXT}"),
            ("Pools", f"{nb} \u2192 {na} ({', '.join(map(str, sd.get('pools_before', []))) or '-'}"
                      + (f" + {', '.join(map(str, building))} being built" if building else "")
                      + f" \u2192 {', '.join(map(str, sd.get('pools_after', []))) or '-'})"),
            ("Pools removed", ", ".join(f"pool {r.pool} ({r.seconds:.1f} s)" for r in removed) or "none"
             + (" (the compose-declared pools cover the spare count; nothing above it was running)"
                if not removed else ""))]
    if per:
        rows.append(("Reserved by container limits",
                     f"{nb * per:,.0f} MB / {nb * sd.get('cpus_per_pool', 0):g} CPUs \u2192 "
                     f"{na * per:,.0f} MB / {na * sd.get('cpus_per_pool', 0):g} CPUs"))
    if before and after:
        rows += [("Memory in use (measured)", f"{before.mem_mb:,.0f} MB \u2192 {after.mem_mb:,.0f} MB "
                  f"({after.mem_mb - before.mem_mb:+,.0f} MB)"),
                 ("CPU in use (measured)", f"{before.cpu_percent:.0f} % \u2192 {after.cpu_percent:.0f} %"),
                 ("Containers running", f"{before.containers} \u2192 {after.containers}")]
    else:
        rows.append(("Measured use", "no resource samples around the scale-down"))
    out.append('<table width="100%" cellspacing="0" cellpadding="4" border="1" '
               'style="border-collapse:collapse; color:#333;">'
               + "".join(f'<tr><td width="32%"><b>{_esc(k)}</b></td><td>{_esc(v)}</td></tr>' for k, v in rows)
               + '</table>')
    idle = [r for r in summ.removals if not r.forced]
    if idle:
        out.append('<p style="color:#555;">Also removed during the run for being idle: '
                   + _esc(", ".join(f"pool {r.pool} (idle {r.idle:.0f} s)" for r in idle)) + '.</p>')
    return "".join(out)


def _round_robin_html(data: PoolTestData) -> str:
    """Both round-robin cases, explicitly: A (no free pool yet, scaling) and
    B (resource limit reached, no more pools)."""
    summ = scaling_summary(data)
    frames = data.frames
    name = lambda w: frames[w].label if w < len(frames) else f"Window {w + 1}"   # noqa: E731
    status = (data.pool_state or {}).get("status") or {}
    out = ['<h2 style="color:#222;">Round-robin assignment</h2>',
           '<p style="color:#555;">A diverted session is only ever put on a pool another session '
           'uses in two situations, both handled round-robin over the ready pools:</p>',
           '<h3 style="color:#222;">A. Not scaled up yet (no free pool, more can be built)</h3>']
    if summ.borrow:
        out.append('<table width="100%" cellspacing="0" cellpadding="4" border="1" '
                   'style="border-collapse:collapse; color:#333;"><tr><th>Window</th><th>Borrowed</th>'
                   '<th>From</th><th>Until</th><th>Waited</th><th>Outcome</th></tr>' + "".join(
                       f'<tr><td>{_esc(name(c.window))}</td><td>pool {c.borrowed}</td>'
                       f'<td>{_mmss(c.start)}</td><td>{_mmss(c.end) if c.end is not None else "end of run"}</td>'
                       f'<td>{_secs((c.end - c.start) if c.end is not None else None)}'
                       f'{" (pool_manager: " + _secs(c.waited) + ")" if c.waited is not None else ""}</td>'
                       f'<td>{_esc({"own": f"moved to its own pool {c.own_pool}", "dropped": "limit reached: stays shared (case B)", "waiting": "still waiting"}[c.outcome])}</td></tr>'
                       for c in summ.borrow) + '</table>')
    else:
        out.append('<p style="color:#555;">Not observed: every window found a free pool the moment '
                   'it was diverted.' + (' The delayed windows waited for pre-built pools, which is '
                                         'how this case is avoided.' if data.delayed else '') + '</p>')
    out.append('<h3 style="color:#222;">B. Resource limit reached (no more pools can be built)</h3>')
    if summ.capped:
        out.append('<p style="color:#555;">' + "<br/>".join(
            f"Growth capped at {_mmss(t)}: {_esc(r)}" for t, r in summ.capped) + '</p>')
    if summ.limit:
        out.append('<table width="100%" cellspacing="0" cellpadding="4" border="1" '
                   'style="border-collapse:collapse; color:#333;"><tr><th>Window</th><th>Pool</th>'
                   '<th>Since</th><th>Shares with</th><th>How</th></tr>' + "".join(
                       f'<tr><td>{_esc(name(c.window))}</td><td>pool {c.pool}</td><td>{_mmss(c.since)}</td>'
                       f'<td>{_esc(", ".join(name(o) for o in c.shared_with) or "a session outside the test")}</td>'
                       f'<td>{_esc(c.how)}</td></tr>' for c in summ.limit) + '</table>')
    else:
        room = status.get("room")
        free = len((data.pool_state or {}).get("free", []))
        hint = (f" At the end there was room for {room} more pool(s) and {free} free one(s): "
                f"run with more than {room + free} additional diverted windows, or lower "
                "POOL_MAX_MEMORY_MB / POOL_MAX_CPUS / POOL_MAX, to see this case."
                if isinstance(room, int) else "")
        out.append('<p style="color:#555;">Not observed: the resource limit was not reached during '
                   'the run.' + _esc(hint) + '</p>')
    return "".join(out)
