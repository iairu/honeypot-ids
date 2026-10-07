"""Renders a core.pool_test_report.PoolTestData to a PDF: which honeypot pool
each test window's session landed in, and whether that matches the rule of
one malicious session per pool (shared only when pools run out).

GUI-thread only, same print machinery and Baskerville styling as
core/exploit_report_pdf.py."""
from __future__ import annotations

from PyQt6.QtCore import QMarginsF, QSizeF, QUrl
from PyQt6.QtGui import QFont, QPageLayout, QPageSize
from PyQt6.QtPrintSupport import QPrinter
from PyQt6.QtGui import QColor, QTextDocument

from core import diagrams, pool_evidence, vector_figures
from core.diagrams import _arrow, _box, _new
from core.exploit_report_pdf import (_FONT_CSS_STACK, _GREEN, _GREY, _ORANGE, _RED, _badge, _esc,
                                     _pool_state_html, _report_font_family)
from core.pool_test_report import (CART_LOST, EXCLUSIVE, INCOMPLETE, MERGED, SHARED_EXPECTED,
                                   UNSTABLE, PoolTestData, Verdict, analyze, cart_violations)

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
    base: dict[int, object] = {}
    rows = []
    for step in data.steps:
        cells = []
        for i, c in enumerate(step.carts):
            if c is not None and c.items and i not in base:
                base[i] = c
            ref = base.get(i)
            d = step.decisions[i] if i < len(step.decisions) else None
            where = (f"pool {d.pool}" if d is not None and d.pool is not None else "production")
            if c is None:
                mark = _badge("unreadable", _GREY)
            elif ref is None:
                mark = _badge("no cart yet", _GREY)
            elif c.signature() == ref.signature():
                mark = _badge("same cart", _GREEN)
            else:
                mark = _badge("CART CHANGED", _RED)
            cells.append(f'<td>{mark}<br/><span style="font-size:8pt;color:#555;">on {_esc(where)}</span></td>')
        rows.append(f'<tr><td>{_esc(step.title)}</td>{"".join(cells)}</tr>')
    head = "".join(f"<th>{_esc(f.label)}</th>" for f in data.frames)
    issues = cart_violations(data.steps)
    verdict = ('<p style="color:#2e7d32;"><b>Every cart stayed exactly as filled, on production and in '
               'every honeypot pool.</b></p>' if not issues else
               '<ul style="color:#c62828;">' + "".join(f"<li>{_esc(x)}</li>" for x in issues) + "</ul>")
    return ('<h2 style="color:#222;">Cart persistence</h2>'
            '<p style="color:#555;">A visitor diverted to a honeypot is served by a different database, so '
            'WooCommerce\'s own cart session does not exist there. The storefront therefore carries the '
            'cart in a cookie and rebuilds it on whichever instance serves the next request. Each window '
            'filled its cart on production; the cart was then read back after every step, through the same '
            'cookies and routing as the window\'s own traffic.</p>'
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
    verdict = analyze(data.frames, data.pool_state, data.steps)
    owners = {f.pool: f.label[-1] for f in data.frames if f.pool is not None}
    verdict.findings.extend(pool_evidence.cross_traffic(data.evidence, owners))
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
             f'Windows: {len(data.frames)}</td></tr></table><hr/>',
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
