"""Shared, hand-drawn diagrams for the PDF exports.

QPainter box-and-arrow figures (no external graphing lib) that every PDF export
can embed and cross-reference: a system-architecture map, a request-routing
flow, and the threat-scoring pipeline. Kept deliberately simple and high
contrast so they stay legible when the PDF downscales them to page width.

Each figure returns a QImage; callers add a "Figure N" caption and reference the
others by number.
"""
from __future__ import annotations

import html as _html

from PyQt6.QtCore import QPointF, QRectF, Qt, QUrl
from PyQt6.QtGui import QColor, QFont, QImage, QPainter, QPen, QPolygonF, QTextDocument

# Shared palette (kept close to the report's own band colours).
_BLUE = "#1565c0"
_GREEN = "#2e7d32"
_RED = "#c62828"
_ORANGE = "#e08a00"
_GREY = "#5b6470"
_PURPLE = "#6a3fb0"
_INK = "#1a1a1a"


def _new(w: int, h: int) -> tuple[QImage, QPainter]:
    img = QImage(w, h, QImage.Format.Format_ARGB32)
    img.fill(QColor("#ffffff"))
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    return img, p


def _box(p: QPainter, x, y, w, h, title, subtitle="", *, fill="#ffffff",
         border=_INK, family="Serif", text=_INK) -> tuple[float, float]:
    """Rounded box with a centred (bold) title and optional subtitle. Returns
    the box centre so callers can route arrows to/from it."""
    rect = QRectF(x, y, w, h)
    p.setPen(QPen(QColor(border), 2))
    p.setBrush(QColor(fill))
    p.drawRoundedRect(rect, 8, 8)
    p.setPen(QColor(text))
    if subtitle:
        p.setFont(QFont(family, 10, QFont.Weight.Bold))
        p.drawText(QRectF(x, y + 5, w, h * 0.52),
                   Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
                   title)
        p.setFont(QFont(family, 8))
        p.drawText(QRectF(x + 4, y + h * 0.5, w - 8, h * 0.5 - 4),
                   Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                   subtitle)
    else:
        p.setFont(QFont(family, 10, QFont.Weight.Bold))
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap, title)
    return x + w / 2, y + h / 2


def _arrow(p: QPainter, x1, y1, x2, y2, *, color=_INK, label="", family="Serif",
           dashed=False, width=2) -> None:
    pen = QPen(QColor(color), width)
    if dashed:
        pen.setStyle(Qt.PenStyle.DashLine)
    p.setPen(pen)
    p.drawLine(int(x1), int(y1), int(x2), int(y2))
    # Arrowhead.
    import math
    ang = math.atan2(y2 - y1, x2 - x1)
    size = 9
    tip = QPointF(x2, y2)
    left = QPointF(x2 - size * math.cos(ang - 0.5), y2 - size * math.sin(ang - 0.5))
    right = QPointF(x2 - size * math.cos(ang + 0.5), y2 - size * math.sin(ang + 0.5))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(color))
    p.drawPolygon(QPolygonF([tip, left, right]))
    if label:
        p.setPen(QColor(color))
        p.setFont(QFont(family, 7))
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        p.drawText(int(mx) + 4, int(my) - 3, label)


# ---- figures ----

def architecture_diagram(family: str = "Serif") -> QImage:
    """The service topology: clients -> reverse proxy -> production/honeypot
    eshops + their databases, with Redis, Suricata and the SIEM alongside."""
    img, p = _new(920, 540)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 24, "System architecture")

    cx = 460
    c = _box(p, cx - 90, 40, 180, 44, "Internet / clients", family=family, fill="#eef2f7")
    proxy = _box(p, cx - 150, 130, 300, 62, "Reverse proxy",
                 "OpenResty + Lua: threat scoring & routing",
                 fill="#e7effa", border=_BLUE, text=_BLUE, family=family)
    redis = _box(p, 40, 138, 170, 50, "session_store (Redis)",
                 "sessions, IP reputation", fill="#eef0f2", border=_GREY, text=_GREY, family=family)
    suri = _box(p, 710, 138, 170, 50, "Suricata IDS",
                "network alerts -> reputation", fill="#fdf1e3", border=_ORANGE, text=_ORANGE, family=family)
    prod = _box(p, 150, 270, 230, 58, "Production eshop",
                "WordPress / WooCommerce", fill="#e8f3ea", border=_GREEN, text=_GREEN, family=family)
    hpot = _box(p, 540, 270, 230, 58, "Honeypot eshop(s)",
                "decoy WordPress", fill="#f8e7e7", border=_RED, text=_RED, family=family)
    pdb = _box(p, 185, 372, 160, 46, "Production DB", "MySQL",
               fill="#eef0f2", border=_GREY, text=_GREY, family=family)
    hdb = _box(p, 575, 372, 160, 46, "Honeypot DB", "MySQL (decoy)",
               fill="#eef0f2", border=_GREY, text=_GREY, family=family)
    siem = _box(p, 250, 470, 420, 48, "SIEM",
                "Vector -> Elasticsearch -> Kibana", fill="#efe8f7", border=_PURPLE, text=_PURPLE, family=family)

    _arrow(p, c[0], 84, proxy[0], 130, family=family)
    _arrow(p, redis[0] + 85, redis[1], proxy[0] - 150, proxy[1], color=_GREY, family=family, dashed=True)
    _arrow(p, suri[0] - 85, suri[1], proxy[0] + 150, proxy[1], color=_ORANGE, family=family, dashed=True)
    _arrow(p, proxy[0] - 60, 192, prod[0], 270, color=_GREEN, family=family, label="clean")
    _arrow(p, proxy[0] + 60, 192, hpot[0], 270, color=_RED, family=family, label="suspicious")
    _arrow(p, prod[0], 328, pdb[0], 372, color=_GREY, family=family)
    _arrow(p, hpot[0], 328, hdb[0], 372, color=_GREY, family=family)
    _arrow(p, proxy[0], 192, siem[0], 470, color=_PURPLE, family=family, dashed=True, label="logs")
    _arrow(p, suri[0], 188, siem[0] + 180, 470, color=_PURPLE, family=family, dashed=True)
    p.end()
    return img


def request_flow_diagram(family: str = "Serif") -> QImage:
    """How one request is classified and routed."""
    img, p = _new(920, 300)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 24, "Request routing")

    req = _box(p, 30, 110, 150, 60, "Client request", family=family, fill="#eef2f7")
    ana = _box(p, 250, 105, 200, 70, "Reverse proxy",
               "score the request, then decide", fill="#e7effa", border=_BLUE, text=_BLUE, family=family)
    dec = _box(p, 520, 105, 170, 70, "Route?",
               "CVE match / high score / bad IP / sticky", fill="#fff7e6", border=_ORANGE, text=_ORANGE, family=family)
    hp = _box(p, 750, 40, 150, 56, "Honeypot", "decoy shop",
              fill="#f8e7e7", border=_RED, text=_RED, family=family)
    pr = _box(p, 750, 180, 150, 56, "Production", "real shop",
              fill="#e8f3ea", border=_GREEN, text=_GREEN, family=family)

    _arrow(p, req[0] + 75, req[1], 250, ana[1], family=family)
    _arrow(p, ana[0] + 100, ana[1], 520, dec[1], family=family)
    _arrow(p, dec[0] + 85, dec[1] - 15, hp[0] - 75, hp[1] + 5, color=_RED, family=family, label="any trigger")
    _arrow(p, dec[0] + 85, dec[1] + 15, pr[0] - 75, pr[1] - 5, color=_GREEN, family=family, label="otherwise")
    p.end()
    return img


def scoring_pipeline_diagram(family: str = "Serif") -> QImage:
    """The threat-score accumulation pipeline."""
    img, p = _new(920, 260)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 24, "Threat-scoring pipeline")

    stages = [
        ("URI patterns", "+15 each", "#e7effa", _BLUE),
        ("CVE patterns", "+40", "#f8e7e7", _RED),
        ("Headers / method", "+N", "#fdf1e3", _ORANGE),
        ("IP reputation", "Suricata, decayed", "#fdf1e3", _ORANGE),
        ("Accumulate + decay", "session peak", "#eef0f2", _GREY),
    ]
    x = 24
    w = 158
    gap = 14
    y = 90
    h = 74
    prev = None
    for title, sub, fill, border in stages:
        c = _box(p, x, y, w, h, title, sub, fill=fill, border=border, text=border, family=family)
        if prev is not None:
            _arrow(p, prev[0] + w / 2, y + h / 2, x, y + h / 2, family=family)
        prev = (x, c[1])
        x += w + gap
    # final -> route
    route = _box(p, x, y, 120, h, "Route", "prod / honeypot",
                 fill="#e8f3ea", border=_GREEN, text=_GREEN, family=family)
    _arrow(p, prev[0] + w / 2, y + h / 2, x, y + h / 2, family=family)
    p.setFont(QFont(family, 8))
    p.setPen(QColor(_GREY))
    p.drawText(24, y + h + 34,
               "Signals accumulate onto the session's peak (capped at 100) and fade over time; "
               "a CVE match or bad IP can divert to the honeypot on its own.")
    p.end()
    return img


def figure_html(doc: QTextDocument, img: QImage, key: str, number: int,
                caption: str, width: int = 620) -> str:
    """Embed a figure into `doc` and return the <img> + numbered caption HTML.
    Callers reference it elsewhere as "Figure {number}"."""
    doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(f"diagram://{key}"), img)
    cap = _html.escape(caption)
    return (f'<div><img src="diagram://{key}" width="{width}"/><br/>'
            f'<span style="color:#666; font-size:9pt;"><b>Figure {number}.</b> {cap}</span>'
            '</div><br/>')
