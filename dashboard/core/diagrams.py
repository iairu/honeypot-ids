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
         border=_INK, family="Serif", text=_INK, draw=True) -> tuple[float, float]:
    """Rounded box with a centred (bold) title and optional subtitle. Returns
    the box centre so callers can route arrows to/from it. With ``draw=False``
    it only computes the centre (a layout pass) and paints nothing -- callers
    use that to draw all the arrows FIRST, then the boxes on top, so arrows
    never overlap a box. Title and subtitle both word-wrap to stay inside."""
    cx, cy = x + w / 2, y + h / 2
    if not draw:
        return cx, cy
    _WRAP = Qt.TextFlag.TextWordWrap
    rect = QRectF(x, y, w, h)
    p.setPen(QPen(QColor(border), 2))
    p.setBrush(QColor(fill))
    p.drawRoundedRect(rect, 8, 8)
    p.setPen(QColor(text))
    if subtitle:
        p.setFont(QFont(family, 10, QFont.Weight.Bold))
        # Title: top half, bottom-aligned so it sits just above the subtitle.
        p.drawText(QRectF(x + 3, y + 3, w - 6, h * 0.48),
                   Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom | _WRAP,
                   title)
        p.setFont(QFont(family, 8))
        # Subtitle: below the title with a little extra top padding.
        p.drawText(QRectF(x + 4, y + h * 0.52 + 4, w - 8, h * 0.48 - 6),
                   Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop | _WRAP,
                   subtitle)
    else:
        p.setFont(QFont(family, 10, QFont.Weight.Bold))
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter | _WRAP, title)
    return cx, cy


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
    # (key, x, y, w, h, title, subtitle, fill, border)
    specs = [
        ("client", cx - 90, 40, 180, 44, "Internet / clients", "", "#eef2f7", _INK),
        ("proxy", cx - 150, 130, 300, 62, "Reverse proxy",
         "OpenResty + Lua: threat scoring & routing", "#e7effa", _BLUE),
        ("redis", 40, 138, 170, 50, "session_store (Redis)",
         "sessions, IP reputation", "#eef0f2", _GREY),
        ("suri", 710, 138, 170, 50, "Suricata IDS",
         "network alerts -> reputation", "#fdf1e3", _ORANGE),
        ("prod", 150, 270, 230, 58, "Production eshop",
         "WordPress / WooCommerce", "#e8f3ea", _GREEN),
        ("hpot", 540, 270, 230, 58, "Honeypot eshop(s)",
         "decoy WordPress", "#f8e7e7", _RED),
        ("pdb", 185, 372, 160, 46, "Production DB", "MySQL", "#eef0f2", _GREY),
        ("hdb", 575, 372, 160, 46, "Honeypot DB", "MySQL (decoy)", "#eef0f2", _GREY),
        ("siem", 250, 470, 420, 48, "SIEM",
         "Vector -> Elasticsearch -> Kibana", "#efe8f7", _PURPLE),
    ]
    C = {s[0]: (s[1] + s[3] / 2, s[2] + s[4] / 2) for s in specs}

    # Arrows first, so the boxes drawn afterwards sit ON TOP of the arrow ends.
    _arrow(p, C["client"][0], 84, C["proxy"][0], 130, family=family)
    _arrow(p, C["redis"][0] + 85, C["redis"][1], C["proxy"][0] - 150, C["proxy"][1], color=_GREY, family=family, dashed=True)
    _arrow(p, C["suri"][0] - 85, C["suri"][1], C["proxy"][0] + 150, C["proxy"][1], color=_ORANGE, family=family, dashed=True)
    _arrow(p, C["proxy"][0] - 60, 192, C["prod"][0], 270, color=_GREEN, family=family, label="clean")
    _arrow(p, C["proxy"][0] + 60, 192, C["hpot"][0], 270, color=_RED, family=family, label="suspicious")
    _arrow(p, C["prod"][0], 328, C["pdb"][0], 372, color=_GREY, family=family)
    _arrow(p, C["hpot"][0], 328, C["hdb"][0], 372, color=_GREY, family=family)
    _arrow(p, C["proxy"][0], 192, C["siem"][0], 470, color=_PURPLE, family=family, dashed=True, label="logs")
    _arrow(p, C["suri"][0], 188, C["siem"][0] + 180, 470, color=_PURPLE, family=family, dashed=True)

    for _k, bx, by, bw, bh, t, s, fill, bd in specs:
        _box(p, bx, by, bw, bh, t, s, fill=fill, border=bd, text=bd, family=family)
    p.end()
    return img


def request_flow_diagram(family: str = "Serif") -> QImage:
    """How one request is classified and routed."""
    img, p = _new(920, 300)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 24, "Request routing")

    specs = [
        ("req", 30, 110, 150, 60, "Client request", "", "#eef2f7", _INK),
        ("ana", 250, 105, 200, 70, "Reverse proxy",
         "score the request, then decide", "#e7effa", _BLUE),
        ("dec", 520, 105, 170, 70, "Route?",
         "CVE match / high score / bad IP / sticky", "#fff7e6", _ORANGE),
        ("hp", 750, 40, 150, 56, "Honeypot", "decoy shop", "#f8e7e7", _RED),
        ("pr", 750, 180, 150, 56, "Production", "real shop", "#e8f3ea", _GREEN),
    ]
    C = {s[0]: (s[1] + s[3] / 2, s[2] + s[4] / 2) for s in specs}

    _arrow(p, C["req"][0] + 75, C["req"][1], 250, C["ana"][1], family=family)
    _arrow(p, C["ana"][0] + 100, C["ana"][1], 520, C["dec"][1], family=family)
    _arrow(p, C["dec"][0] + 85, C["dec"][1] - 15, C["hp"][0] - 75, C["hp"][1] + 5, color=_RED, family=family, label="any trigger")
    _arrow(p, C["dec"][0] + 85, C["dec"][1] + 15, C["pr"][0] - 75, C["pr"][1] - 5, color=_GREEN, family=family, label="otherwise")

    for _k, bx, by, bw, bh, t, s, fill, bd in specs:
        _box(p, bx, by, bw, bh, t, s, fill=fill, border=bd, text=bd, family=family)
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
    w = 158
    gap = 14
    y = 90
    h = 74
    # Lay out the pipeline stages + the final "Route" box left to right.
    boxes = []  # (x, w2, title, subtitle, fill, border)
    x = 24
    for title, sub, fill, border in stages:
        boxes.append((x, w, title, sub, fill, border))
        x += w + gap
    boxes.append((x, 120, "Route", "prod / honeypot", "#e8f3ea", _GREEN))

    # Arrows first (behind), connecting consecutive box centres.
    for i in range(len(boxes) - 1):
        bx, bw, *_ = boxes[i]
        nx, *_ = boxes[i + 1]
        _arrow(p, bx + bw, y + h / 2, nx, y + h / 2, family=family)
    # Boxes on top.
    for bx, bw, title, sub, fill, border in boxes:
        _box(p, bx, y, bw, h, title, sub, fill=fill, border=border, text=border, family=family)

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
