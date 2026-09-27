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
import math

from PyQt6.QtCore import QPointF, QRect, QRectF, Qt, QUrl
from PyQt6.QtGui import (QColor, QFont, QFontMetrics, QImage, QPainter, QPen,
                         QPolygonF, QTextDocument)

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


def request_flow_diagram(family: str = "Serif") -> QImage:
    """How one request is classified and routed."""
    img, p = _new(920, 300)
    p.setFont(QFont(family, 12, QFont.Weight.Bold))
    p.setPen(QColor(_INK))
    p.drawText(20, 24, "Request routing")

    specs = [
        ("req", 20, 110, 140, 64, "Client request", "", "#eef2f7", _INK),
        ("ana", 215, 102, 190, 80, "Reverse proxy",
         "score the request, then decide", "#e7effa", _BLUE),
        ("dec", 460, 97, 190, 90, "Route?",
         "CVE match / high score / bad IP / sticky", "#fff7e6", _ORANGE),
        ("hp", 770, 40, 130, 60, "Honeypot", "decoy shop", "#f8e7e7", _RED),
        ("pr", 770, 184, 130, 60, "Production", "real shop", "#e8f3ea", _GREEN),
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
               "(unless THREAT_DECAY_ENABLED=false); a CVE match or bad IP can divert to the "
               "honeypot on its own.")
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
