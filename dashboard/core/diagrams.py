"""Shared, hand-drawn diagrams for the PDF exports.

QPainter box-and-arrow figures (no external graphing lib) that every PDF export
can embed and cross-reference: a system-architecture map, a request-routing
flow, and the threat-scoring pipeline. Kept deliberately simple and high
contrast so they stay legible when the PDF downscales them to page width.

Each figure returns a VectorFigure (core/vector_figures.py), so it stays vector
in the PDF; callers add a "Figure N" caption and reference the others by number.
"""
from __future__ import annotations

import html as _html
import math

from PyQt6.QtCore import QPointF, QRect, QRectF, Qt
from PyQt6.QtGui import (QColor, QFont, QFontMetrics, QPainter, QPen,
                         QPolygonF, QTextDocument)

from core import honeypot_layer
from core.vector_figures import VectorFigure, add_figure, new_figure

# Shared palette (kept close to the report's own band colours).
_BLUE = "#1565c0"
_GREEN = "#2e7d32"
_RED = "#c62828"
_ORANGE = "#e08a00"
_GREY = "#5b6470"
_PURPLE = "#6a3fb0"
_INK = "#1a1a1a"

# Top padding (px) between a box's title and its subtitle (bottom text).
_SUBTITLE_GAP = 7


def _new(w: int, h: int) -> tuple[VectorFigure, QPainter]:
    return new_figure(w, h)


def _box(p: QPainter, x, y, w, h, title, subtitle="", *, fill="#ffffff",
         border=_INK, family="Serif", text=_INK, draw=True) -> tuple[float, float]:
    """Rounded box with a centred (bold) title and optional subtitle. Returns
    the box centre so callers can route arrows to/from it. With ``draw=False``
    it only computes the centre (a layout pass) and paints nothing -- callers
    draw all the arrows FIRST, then the boxes on top, so arrows never overlap
    a box. Title and subtitle both word-wrap to the box width; their wrapped
    heights are measured so the pair is centred vertically as one block, with
    a fixed gap of top padding above the subtitle (bottom text)."""
    cx, cy = x + w / 2, y + h / 2
    if not draw:
        return cx, cy
    flags = int(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop) | int(Qt.TextFlag.TextWordWrap)
    pad_x = 6
    inner_w = max(10, int(w - 2 * pad_x))
    title_font = QFont(family, 10, QFont.Weight.Bold)
    sub_font = QFont(family, 8)

    def _measure(font: QFont, s: str) -> int:
        return QFontMetrics(font).boundingRect(QRect(0, 0, inner_w, 10_000), flags, s).height()

    th = _measure(title_font, title)
    sh = _measure(sub_font, subtitle) if subtitle else 0
    gap = _SUBTITLE_GAP if subtitle else 0
    block = th + gap + sh
    top = y + max(3.0, (h - block) / 2)

    p.setPen(QPen(QColor(border), 2))
    p.setBrush(QColor(fill))
    p.drawRoundedRect(QRectF(x, y, w, h), 8, 8)
    p.setPen(QColor(text))
    p.setFont(title_font)
    p.drawText(QRectF(x + pad_x, top, inner_w, th + 2), flags, title)
    if subtitle:
        p.setFont(sub_font)
        p.drawText(QRectF(x + pad_x, top + th + gap, inner_w, sh + 2), flags, subtitle)
    return cx, cy


def _head(p: QPainter, x1, y1, x2, y2, color) -> None:
    ang = math.atan2(y2 - y1, x2 - x1)
    size = 9
    tip = QPointF(x2, y2)
    left = QPointF(x2 - size * math.cos(ang - 0.5), y2 - size * math.sin(ang - 0.5))
    right = QPointF(x2 - size * math.cos(ang + 0.5), y2 - size * math.sin(ang + 0.5))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(color))
    p.drawPolygon(QPolygonF([tip, left, right]))


def _arrow(p: QPainter, *pts, color=_INK, dashed=False, width=2) -> None:
    """Arrow along a polyline: ``_arrow(p, x1, y1, x2, y2[, x3, y3 ...])``.
    Extra points let an arrow route AROUND boxes instead of through them.
    Labels are drawn separately (``_label``) after the boxes, so they are
    never hidden behind a box."""
    xy = [(float(pts[i]), float(pts[i + 1])) for i in range(0, len(pts), 2)]
    pen = QPen(QColor(color), width)
    if dashed:
        pen.setStyle(Qt.PenStyle.DashLine)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    for (ax, ay), (bx, by) in zip(xy, xy[1:]):
        p.drawLine(QPointF(ax, ay), QPointF(bx, by))
    (ax, ay), (bx, by) = xy[-2], xy[-1]
    _head(p, ax, ay, bx, by, color)


def _label(p: QPainter, x, y, text, *, color=_INK, family="Serif") -> None:
    """Small arrow label centred on (x, y) over a white backing, drawn after
    the boxes so it stays readable on top of the line it names."""
    font = QFont(family, 7)
    fm = QFontMetrics(font)
    tw, th = fm.horizontalAdvance(text) + 6, fm.height() + 2
    r = QRectF(x - tw / 2, y - th / 2, tw, th)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#ffffff"))
    p.drawRoundedRect(r, 3, 3)
    p.setPen(QColor(color))
    p.setFont(font)
    p.drawText(r, Qt.AlignmentFlag.AlignCenter, text)


# ---- figures ----

def architecture_diagram(family: str = "Serif") -> VectorFigure:
    """The service topology: clients -> reverse proxy -> production/honeypot
    eshops + their databases, with Redis, Suricata and the SIEM alongside.
    In the database proxy honeypot layer (core/honeypot_layer.py) the middle
    shows the one eshop switching databases instead."""
    if honeypot_layer.is_database():
        return _db_proxy_architecture_diagram(family)
    img, p = _new(920, 540)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 24, "System architecture")

    cx = 460
    # (key, x, y, w, h, title, subtitle, fill, border)
    specs = [
        ("client", cx - 90, 40, 180, 44, "Internet / clients", "", "#eef2f7", _INK),
        ("proxy", cx - 150, 130, 300, 62, "Reverse proxy",
         "OpenResty + Lua: threat scoring & routing", "#e7effa", _BLUE),
        ("redis", 30, 132, 190, 60, "session_store (Redis)",
         "sessions, IP reputation", "#eef0f2", _GREY),
        ("suri", 700, 132, 190, 60, "Suricata IDS",
         "network alerts -> reputation", "#fdf1e3", _ORANGE),
        ("prod", 150, 270, 230, 58, "Production eshop",
         "WordPress / WooCommerce", "#e8f3ea", _GREEN),
        ("hpot", 540, 270, 230, 58, "Honeypot eshop(s)",
         "decoy WordPress", "#f8e7e7", _RED),
        ("pdb", 185, 372, 160, 50, "Production DB", "MySQL", "#eef0f2", _GREY),
        ("hdb", 575, 372, 160, 50, "Honeypot DB", "MySQL (decoy)", "#eef0f2", _GREY),
        ("siem", 250, 470, 420, 52, "SIEM",
         "Vector -> Elasticsearch -> Kibana", "#efe8f7", _PURPLE),
    ]
    C = {s[0]: (s[1] + s[3] / 2, s[2] + s[4] / 2) for s in specs}

    # Arrows first, so the boxes drawn afterwards sit ON TOP of the arrow ends.
    _arrow(p, C["client"][0], 84, C["proxy"][0], 130)
    _arrow(p, 220, C["redis"][1], 310, C["proxy"][1], color=_GREY, dashed=True)
    _arrow(p, 700, C["suri"][1], 610, C["proxy"][1], color=_ORANGE, dashed=True)
    _arrow(p, C["proxy"][0] - 60, 192, C["prod"][0], 270, color=_GREEN)
    _arrow(p, C["proxy"][0] + 60, 192, C["hpot"][0], 270, color=_RED)
    _arrow(p, C["prod"][0], 328, C["pdb"][0], 372, color=_GREY)
    _arrow(p, C["hpot"][0], 328, C["hdb"][0], 372, color=_GREY)
    _arrow(p, C["proxy"][0], 192, C["siem"][0], 470, color=_PURPLE, dashed=True)
    # Suricata -> SIEM routes down the right margin, clear of the honeypot
    # boxes, then turns into the SIEM box's right edge.
    _arrow(p, 840, 192, 840, C["siem"][1], 670, C["siem"][1], color=_PURPLE, dashed=True)

    for _k, bx, by, bw, bh, t, s, fill, bd in specs:
        _box(p, bx, by, bw, bh, t, s, fill=fill, border=bd, text=bd, family=family)

    _label(p, (C["proxy"][0] - 60 + C["prod"][0]) / 2, 231, "clean", color=_GREEN, family=family)
    _label(p, (C["proxy"][0] + 60 + C["hpot"][0]) / 2, 231, "suspicious", color=_RED, family=family)
    _label(p, C["proxy"][0], 440, "logs", color=_PURPLE, family=family)
    _label(p, 840, 440, "alerts", color=_PURPLE, family=family)
    p.end()
    return img


def _db_proxy_architecture_diagram(family: str) -> VectorFigure:
    """architecture_diagram() for the database proxy layer: the proxy forwards
    everything to ONE eshop, whose db.php drop-in connects to the production
    or the honeypot database per request (X-Honeypot-Backend header)."""
    img, p = _new(920, 540)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 24, "System architecture (database proxy layer)")

    cx = 460
    specs = [
        ("client", cx - 90, 40, 180, 44, "Internet / clients", "", "#eef2f7", _INK),
        ("proxy", cx - 150, 130, 300, 62, "Reverse proxy",
         "OpenResty + Lua: scores and tags each request", "#e7effa", _BLUE),
        ("redis", 30, 132, 190, 60, "session_store (Redis)",
         "sessions, IP reputation", "#eef0f2", _GREY),
        ("suri", 700, 132, 190, 60, "Suricata IDS",
         "network alerts -> reputation", "#fdf1e3", _ORANGE),
        ("shop", cx - 160, 254, 320, 62, "Eshop (one WordPress)",
         "db.php picks the database per request", "#e7effa", _BLUE),
        ("pdb", 150, 372, 230, 50, "Production DB", "MySQL, real data", "#e8f3ea", _GREEN),
        ("hdb", 540, 372, 230, 50, "Honeypot DB", "MySQL, scrubbed clone", "#f8e7e7", _RED),
        ("siem", 250, 470, 420, 52, "SIEM",
         "Vector -> Elasticsearch -> Kibana", "#efe8f7", _PURPLE),
    ]
    C = {s[0]: (s[1] + s[3] / 2, s[2] + s[4] / 2) for s in specs}

    _arrow(p, C["client"][0], 84, C["proxy"][0], 130)
    _arrow(p, 220, C["redis"][1], 310, C["proxy"][1], color=_GREY, dashed=True)
    _arrow(p, 700, C["suri"][1], 610, C["proxy"][1], color=_ORANGE, dashed=True)
    _arrow(p, C["proxy"][0], 192, C["shop"][0], 254, color=_BLUE)
    _arrow(p, C["shop"][0] - 90, 316, C["pdb"][0], 372, color=_GREEN)
    _arrow(p, C["shop"][0] + 90, 316, C["hdb"][0], 372, color=_RED)
    # Proxy logs -> SIEM route out to the left margin, clear of the eshop and
    # database boxes; Suricata alerts down the right margin.
    _arrow(p, 330, 192, 330, 225, 110, 225, 110, C["siem"][1], 250, C["siem"][1],
           color=_PURPLE, dashed=True)
    _arrow(p, 840, 192, 840, C["siem"][1], 670, C["siem"][1], color=_PURPLE, dashed=True)

    for _k, bx, by, bw, bh, t, s, fill, bd in specs:
        _box(p, bx, by, bw, bh, t, s, fill=fill, border=bd, text=bd, family=family)

    _label(p, C["proxy"][0], 223, "all traffic", color=_BLUE, family=family)
    _label(p, (C["shop"][0] - 90 + C["pdb"][0]) / 2, 344, "clean", color=_GREEN, family=family)
    _label(p, (C["shop"][0] + 90 + C["hdb"][0]) / 2, 344, "suspicious", color=_RED, family=family)
    _label(p, 110, 440, "logs", color=_PURPLE, family=family)
    _label(p, 840, 440, "alerts", color=_PURPLE, family=family)
    p.end()
    return img


def request_flow_diagram(family: str = "Serif") -> VectorFigure:
    """How one request is classified and routed. In the database proxy layer
    the two outcomes are the same shop on different databases."""
    db_layer = honeypot_layer.is_database()
    img, p = _new(920, 300)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 24, "Request routing")

    specs = [
        ("req", 20, 110, 140, 64, "Client request", "", "#eef2f7", _INK),
        ("ana", 215, 102, 190, 80, "Reverse proxy",
         "score the request, then decide", "#e7effa", _BLUE),
        ("dec", 460, 97, 190, 90, "Route?",
         "CVE match / high score / sticky session", "#fff7e6", _ORANGE),
        ("hp", 770, 40, 130, 60, "Honeypot",
         "same shop, fake DB" if db_layer else "decoy shop", "#f8e7e7", _RED),
        ("pr", 770, 184, 130, 60, "Production",
         "same shop, real DB" if db_layer else "real shop", "#e8f3ea", _GREEN),
    ]
    C = {s[0]: (s[1] + s[3] / 2, s[2] + s[4] / 2) for s in specs}

    _arrow(p, 160, C["req"][1], 215, C["ana"][1])
    _arrow(p, 405, C["ana"][1], 460, C["dec"][1])
    _arrow(p, 650, C["dec"][1] - 20, 770, C["hp"][1] + 8, color=_RED)
    _arrow(p, 650, C["dec"][1] + 20, 770, C["pr"][1] - 8, color=_GREEN)

    for _k, bx, by, bw, bh, t, s, fill, bd in specs:
        _box(p, bx, by, bw, bh, t, s, fill=fill, border=bd, text=bd, family=family)

    _label(p, 710, (C["dec"][1] - 20 + C["hp"][1] + 8) / 2, "any trigger", color=_RED, family=family)
    _label(p, 710, (C["dec"][1] + 20 + C["pr"][1] - 8) / 2, "otherwise", color=_GREEN, family=family)
    p.end()
    return img


def scoring_pipeline_diagram(family: str = "Serif") -> VectorFigure:
    """The threat-score accumulation pipeline."""
    img, p = _new(920, 260)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 24, "Threat-scoring pipeline")

    stages = [
        ("URI patterns", "+15 each", "#e7effa", _BLUE),
        ("CVE patterns", "+40", "#f8e7e7", _RED),
        ("Headers / method", "+N", "#fdf1e3", _ORANGE),
        ("IP reputation", "per address: 0 if shared, max 10", "#fdf1e3", _ORANGE),
        ("Accumulate + decay", "session peak", "#eef0f2", _GREY),
    ]
    # Size the boxes so all six (5 stages + "Route") fit the canvas width
    # with room between them for a visible arrow.
    margin, gap, route_w = 20, 26, 112
    w = (920 - 2 * margin - route_w - gap * len(stages)) / len(stages)
    y = 80
    h = 84
    boxes = []  # (x, w2, title, subtitle, fill, border)
    x = margin
    for title, sub, fill, border in stages:
        boxes.append((x, w, title, sub, fill, border))
        x += w + gap
    boxes.append((x, route_w, "Route", "prod / honeypot", "#e8f3ea", _GREEN))

    # Arrows first (behind), connecting consecutive box edges.
    for i in range(len(boxes) - 1):
        bx, bw, *_ = boxes[i]
        nx, *_ = boxes[i + 1]
        _arrow(p, bx + bw, y + h / 2, nx, y + h / 2)
    # Boxes on top.
    for bx, bw, title, sub, fill, border in boxes:
        _box(p, bx, y, bw, h, title, sub, fill=fill, border=border, text=border, family=family)

    p.setFont(QFont(family, 8))
    p.setPen(QColor(_GREY))
    p.drawText(QRectF(margin, y + h + 22, 920 - 2 * margin, 40),
               int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop) | int(Qt.TextFlag.TextWordWrap),
               "Signals accumulate onto the session's peak (capped at 100) and fade over time "
               "(unless THREAT_DECAY_ENABLED=false); a CVE match can divert to the honeypot on "
               "its own. Address reputation alone cannot (see the routing decision figure).")
    p.end()
    return img


def routing_decision_diagram(family: str = "Serif") -> VectorFigure:
    """The whole routing decision for one request, in the order the reverse
    proxy makes it (nginx.conf access block, threat_analyzer.lua, router.lua's
    decide_route stages): identify the session, score the request, fold it
    into the session, then the first stage that fires sends the request to
    THIS session's honeypot pool; none firing means production. Also states
    what is per session and what is per address, i.e. why users sharing one
    public address (carrier-grade NAT) aren't routed for a neighbour."""
    W, H = 920, 1210
    img, p = _new(W, H)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 24, "Routing decision for one request")

    x, w = 30, 440          # main column
    rx, rw = 620, 280       # outcome column
    gap = 18
    rows = [
        # key, kind, height, title, subtitle
        ("req", "proc", 46, "Request", "dynamic page or API call"),
        ("static", "dec", 46, "Static file?", "CSS, JS, images, fonts"),
        ("ident", "proc", 92, "Identify the session",
         "Signed SERVERID cookie (id + HMAC) -> that session. No valid cookie -> passive "
         "fingerprint (TLS hello, HTTP version, UA, languages, client hints, IP) seen "
         "within 15 min -> same session. Otherwise a new session. Edited cookie: +50."),
        ("score", "proc", 106, "Score this request",
         "The session's own signals: URI and CVE patterns, headers, method, automation and "
         "request rate, admin/login attempts, uploads, prompt injection; honeytoken reuse = 100. "
         "Address reputation (Suricata, AbuseIPDB): 0 on a shared address, at most 10 otherwise."),
        ("acc", "proc", 60, "Fold into the session",
         "fresh score > 10 adds to the session's decayed peak (max 100)"),
        ("s2", "dec", 50, "Already in a pool and score >= 30?", "sticky: keeps the same pool"),
        ("s3", "dec", 46, "Score >= 80?", "threshold"),
        ("s4", "dec", 46, "CVE pattern matched?", ""),
        ("s5", "dec", 46, "Vulnerable plugin endpoint?", "PHP file in a known-vulnerable plugin"),
        ("s6", "dec", 50, "Address reputation > 50?",
         "only if IP_REPUTATION_CAP > 50; never with the default cap"),
        ("s7", "dec", 46, "3rd admin-area request in this session?", ""),
        ("s8", "dec", 46, "5+ suspicious activities in this session?", ""),
        ("s9", "dec", 46, "Rapid automation and score >= 40?", "per-session request streak"),
        ("s10", "dec", 46, "Suspicious upload?", ""),
        ("prod", "out", 50, "Production", "real shop"),
    ]
    pos = {}
    y = 46
    for key, kind, h, *_ in rows:
        pos[key] = (y, h)
        y += h + gap

    def cy(key):
        y0, h = pos[key]
        return y0 + h / 2

    # Outcome boxes on the right.
    hp_top = pos["s2"][0]
    hp_bot = pos["s10"][0] + pos["s10"][1]
    nr_y, nr_h = pos["static"]

    # Arrows first.
    keys = [r[0] for r in rows]
    for a, b in zip(keys, keys[1:]):
        ya, ha = pos[a]
        yb, _ = pos[b]
        _arrow(p, x + w / 2, ya + ha, x + w / 2, yb,
               color=_GREEN if b == "prod" else _INK)
    _arrow(p, x + w, cy("static"), rx, nr_y + nr_h / 2, color=_GREY)
    dec_keys = ["s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10"]
    for k in dec_keys:
        _arrow(p, x + w, cy(k), rx, cy(k), color=_RED, dashed=(k == "s6"))

    # Boxes.
    styles = {
        "proc": ("#e7effa", _BLUE),
        "dec": ("#fff7e6", _ORANGE),
        "out": ("#e8f3ea", _GREEN),
    }
    for key, kind, h, title, sub in rows:
        fill, border = styles[kind]
        if key == "req":
            fill, border = "#eef2f7", _INK
        _box(p, x, pos[key][0], w, h, title, sub, fill=fill, border=border,
             text=border, family=family)
    _box(p, rx, nr_y, rw, nr_h, "Answered by the proxy", "NOT ROUTED",
         fill="#eef0f2", border=_GREY, text=_GREY, family=family)
    _box(p, rx, hp_top, rw, hp_bot - hp_top, "Honeypot pool of THIS session",
         "The first stage that fires assigns a pool to this session (one pool per "
         "session) and the session stays there while its score stays >= 30. Other "
         "sessions on the same public address keep their own route.",
         fill="#f8e7e7", border=_RED, text=_RED, family=family)

    # Labels last, on top of the lines.
    mid = (x + w + rx) / 2
    _label(p, mid, cy("static"), "yes", color=_GREY, family=family)
    for k in dec_keys:
        _label(p, mid, cy(k), "yes", color=_RED, family=family)
    _label(p, x + w / 2 + 22, (pos["s10"][0] + pos["s10"][1] + pos["prod"][0]) / 2,
           "no to all", color=_GREEN, family=family)

    # Per session vs per address note.
    ny = pos["prod"][0] + pos["prod"][1] + 22
    p.setFont(QFont(family, 8))
    p.setPen(QColor(_GREY))
    p.drawText(QRectF(x, ny, W - 2 * x, H - ny - 6),
               int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop) | int(Qt.TextFlag.TextWordWrap),
               "Shared addresses (carrier-grade NAT): everything the client does itself is "
               "counted on its session, including the rate limit, admin/brute-force counters, "
               "timing streaks and upload scores. Only Suricata and AbuseIPDB know addresses; "
               "their reputation is ignored once 2 sessions were active on the address within "
               "an hour and capped at 10 otherwise, which is below the > 10 needed to count as "
               "a new signal, so it cannot divert anyone on its own. An address shared with an "
               "attacker therefore leaves its other users on production. Bound but below 30: "
               "the session is released back to production.")
    p.end()
    return img


def db_proxy_bypass_diagram(family: str = "Serif") -> VectorFigure:
    """Why some CVEs get past the database proxy honeypot: the reverse proxy
    catches them, but their effect lands in the one shared WordPress instance
    (files / PHP runtime), and the honeypot split only happens below that, at
    the database. The reason is written out in red next to the red link."""
    img, p = _new(920, 470)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 24, "Honeypot bypass on the database proxy level")

    cx = 190
    specs = [
        ("client", cx - 110, 44, 220, 46, "Attacker", "file upload / traversal / RCE exploit",
         "#eef2f7", _INK),
        ("proxy", cx - 130, 130, 260, 62, "Reverse proxy",
         "detects the exploit, tags it for the honeypot", "#e7effa", _BLUE),
        ("shop", cx - 130, 250, 260, 70, "WordPress eshop (one, shared)",
         "same files and PHP runtime for production and honeypot", "#fdecea", _RED),
        ("pdb", 20, 390, 160, 52, "Production DB", "real data", "#e8f3ea", _GREEN),
        ("hdb", 200, 390, 160, 52, "Honeypot DB", "scrubbed clone", "#eef0f2", _GREY),
    ]
    C = {s[0]: (s[1] + s[3] / 2, s[2] + s[4] / 2) for s in specs}

    _arrow(p, cx, 90, cx, 130)
    # The problem link: proxy -> the shared WordPress instance, in red.
    _arrow(p, cx, 192, cx, 250, color=_RED, width=4)
    _arrow(p, C["pdb"][0] + 30, 320, C["pdb"][0] + 30, 390, color=_GREEN)
    _arrow(p, C["hdb"][0] - 30, 320, C["hdb"][0] - 30, 390, color=_GREY)
    # The red callout points at the middle of the red link.
    _arrow(p, 470, 221, cx + 14, 221, color=_RED, dashed=True)

    for _k, bx, by, bw, bh, t, sub, fill, bd in specs:
        _box(p, bx, by, bw, bh, t, sub, fill=fill, border=bd, text=bd, family=family)

    _label(p, cx, 356, "honeypot split (db.php)", color=_GREY, family=family)

    wrap = int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop) | int(Qt.TextFlag.TextWordWrap)
    callout = QRectF(470, 130, 430, 172)
    p.setPen(QPen(QColor(_RED), 2))
    p.setBrush(QColor("#fdecea"))
    p.drawRoundedRect(callout, 8, 8)
    p.setPen(QColor(_RED))
    p.setFont(QFont(family, 10, QFont.Weight.Bold))
    p.drawText(callout.adjusted(12, 10, -12, -10), wrap,
               "Why it bypasses the honeypot")
    p.setFont(QFont(family, 9))
    p.drawText(callout.adjusted(12, 34, -12, -10), wrap,
               "The problem is between the reverse proxy and the WordPress instance. "
               "Even when the exploit is detected and routed \"to the honeypot\", it "
               "still reaches the same WordPress that serves production. An uploaded "
               "file or a traversal lands on the shared filesystem, and RCE runs in the "
               "shared PHP runtime, where it can read wp-config.php's production "
               "credentials. The honeypot was done one level lower, at the database, so "
               "it cannot contain an attack that never needs the database.")

    p.setPen(QColor(_GREY))
    p.setFont(QFont(family, 8))
    p.drawText(QRectF(400, 392, 500, 60), wrap,
               "The honeypot only switches which database a request talks to. "
               "Database-layer attacks (SQL injection, options writes) are contained; "
               "everything above that level is shared with production.")
    p.end()
    return img


def figure_html(doc: QTextDocument, img: VectorFigure, key: str, number: int,
                caption: str, width: int = 620) -> str:
    """Embed a figure into `doc` and return the <img> + numbered caption HTML.
    Callers reference it elsewhere as "Figure {number}"."""
    add_figure(doc, f"diagram://{key}", img)
    cap = _html.escape(caption)
    return (f'<div><img src="diagram://{key}" width="{width}"/><br/>'
            f'<span style="color:#666; font-size:9pt;"><b>Figure {number}.</b> {cap}</span>'
            '</div><br/>')
