"""Procedural flat-illustration engine for the Fernhill storefront (QPainter).

Draws consistent "studio shot" product images -- soft backdrop, floor shadow,
one object -- so the demo shop has a coherent look without stock photography.
Run via build_assets.py (needs PyQt6; offscreen is fine)."""
from __future__ import annotations

import math
import random

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import (QBrush, QColor, QFont, QImage, QLinearGradient, QPainter, QPainterPath,
                         QPen, QRadialGradient)

SIZE = 1000
SERIF = "Libre Baskerville"
SANS = "Sans Serif"


def C(h, a=255):
    c = QColor(h)
    c.setAlpha(a)
    return c


def shade(h, f):
    """Lighten (f>1) or darken (f<1) a hex colour."""
    c = QColor(h)
    if f >= 1:
        return QColor.fromHsl(c.hslHue(), c.hslSaturation(), min(255, int(c.lightness() * f)))
    return QColor.fromHsl(c.hslHue(), c.hslSaturation(), int(c.lightness() * f))


def lin(x0, y0, x1, y1, *stops):
    g = QLinearGradient(x0, y0, x1, y1)
    for pos, col in stops:
        g.setColorAt(pos, QColor(col))
    return QBrush(g)


def canvas(w=SIZE, h=SIZE):
    img = QImage(w, h, QImage.Format.Format_RGB32)
    p = QPainter(img)
    p.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing
                     | QPainter.RenderHint.SmoothPixmapTransform)
    return img, p


def backdrop(p, bg, w=SIZE, h=SIZE, floor=0.72):
    """Soft vertical wall + lighter floor with a horizon line."""
    p.fillRect(0, 0, w, h, lin(0, 0, 0, h, (0, shade(bg, 1.12)), (1, shade(bg, 0.92))))
    p.fillRect(0, int(h * floor), w, h - int(h * floor),
               lin(0, h * floor, 0, h, (0, shade(bg, 0.97)), (1, shade(bg, 0.84))))
    g = QRadialGradient(w * 0.35, h * 0.2, w * 0.8)
    g.setColorAt(0, C("#ffffff", 70))
    g.setColorAt(1, C("#ffffff", 0))
    p.fillRect(0, 0, w, h, QBrush(g))


def floor_shadow(p, cx, cy, w, h=None, a=90):
    h = h or w * 0.16
    g = QRadialGradient(cx, cy, w / 2)
    g.setColorAt(0, C("#000000", a))
    g.setColorAt(1, C("#000000", 0))
    p.save()
    p.translate(cx, cy)
    p.scale(1, h / w)
    p.translate(-cx, -cy)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(g))
    p.drawEllipse(QPointF(cx, cy), w / 2, w / 2)
    p.restore()


def text(p, s, rect, size, color="#222", font=SERIF, bold=False, align=Qt.AlignmentFlag.AlignCenter,
         spacing=0.0, italic=False):
    f = QFont(font, 1)
    f.setPixelSize(size)
    f.setBold(bold)
    f.setItalic(italic)
    f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, spacing)
    p.setFont(f)
    p.setPen(QColor(color))
    p.drawText(QRectF(*rect), int(align) | int(Qt.TextFlag.TextWordWrap), s)


def bean(p, x, y, r, ang, col="#4a2e1d"):
    p.save()
    p.translate(x, y)
    p.rotate(ang)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(lin(-r, -r, r, r, (0, shade(col, 1.5)), (1, shade(col, 0.7))))
    p.drawEllipse(QPointF(0, 0), r, r * 0.68)
    p.setPen(QPen(shade(col, 0.45), max(1.5, r * 0.09)))
    path = QPainterPath()
    path.moveTo(-r * 0.85, 0)
    path.cubicTo(-r * 0.3, -r * 0.35, r * 0.3, r * 0.35, r * 0.85, 0)
    p.drawPath(path)
    p.restore()


def scatter_beans(p, rng, n, area, avoid=None, col="#4a2e1d"):
    x0, y0, x1, y1 = area
    for _ in range(n):
        x, y = rng.uniform(x0, x1), rng.uniform(y0, y1)
        if avoid and avoid[0] < x < avoid[2] and avoid[1] < y < avoid[3]:
            continue
        bean(p, x, y, rng.uniform(15, 24), rng.uniform(0, 180), col)


def gloss(p, path, a=70):
    p.save()
    p.setClipPath(path)
    b = path.boundingRect()
    g = QLinearGradient(b.left(), 0, b.left() + b.width() * 0.5, 0)
    g.setColorAt(0, C("#ffffff", a))
    g.setColorAt(0.5, C("#ffffff", 0))
    p.fillRect(b, QBrush(g))
    p.restore()


def rrpath(x, y, w, h, r):
    path = QPainterPath()
    path.addRoundedRect(QRectF(x, y, w, h), r, r)
    return path


def fill(p, path, brush, pen=None):
    p.setPen(pen or Qt.PenStyle.NoPen)
    p.setBrush(brush)
    p.drawPath(path)


# ---------------------------------------------------------------- objects

def obj_bag(p, cx, base, col, accent, name, sub, w=380, h=560, cream="#f4ead8"):
    x, top = cx - w / 2, base - h
    floor_shadow(p, cx, base + 6, w * 1.15)
    body = QPainterPath()
    body.moveTo(x + 12, top + 40)
    body.lineTo(x + w - 12, top + 40)
    body.quadTo(x + w + 14, top + h * 0.5, x + w - 4, base - 10)
    body.quadTo(cx, base + 14, x + 4, base - 10)
    body.quadTo(x - 14, top + h * 0.5, x + 12, top + 40)
    fill(p, body, lin(x, 0, x + w, 0, (0, shade(col, 0.82)), (0.35, shade(col, 1.12)), (1, shade(col, 0.72))))
    # crimped top
    crimp = QPainterPath()
    crimp.moveTo(x + 10, top + 40)
    crimp.lineTo(x + 10, top)
    crimp.lineTo(x + w - 10, top)
    crimp.lineTo(x + w - 10, top + 40)
    fill(p, crimp, lin(0, top, 0, top + 40, (0, shade(col, 1.25)), (1, shade(col, 0.9))))
    p.setPen(QPen(shade(col, 0.7), 2))
    for i in range(1, 22):
        xx = x + 10 + i * (w - 20) / 22
        p.drawLine(QPointF(xx, top + 2), QPointF(xx, top + 38))
    p.setPen(QPen(C("#000", 40), 3))
    p.drawLine(QPointF(x + 10, top + 40), QPointF(x + w - 10, top + 40))
    # valve
    p.setPen(QPen(shade(col, 0.6), 3))
    p.setBrush(shade(col, 1.2))
    p.drawEllipse(QPointF(cx + w * 0.3, top + 90), 16, 16)
    # label
    lw, lh = w * 0.74, h * 0.52
    lx, ly = cx - lw / 2, top + h * 0.22
    fill(p, rrpath(lx, ly, lw, lh, 10), QBrush(C(cream)), QPen(C(accent), 4))
    text(p, "FERNHILL", (lx, ly + 22, lw, 30), 22, accent, bold=True, spacing=6)
    p.setPen(QPen(C(accent), 2))
    p.drawLine(QPointF(lx + lw * 0.3, ly + 62), QPointF(lx + lw * 0.7, ly + 62))
    text(p, name, (lx + 14, ly + 76, lw - 28, lh * 0.45), 34, "#2b1d14", bold=True)
    text(p, sub, (lx + 14, ly + lh - 92, lw - 28, 40), 18, accent, spacing=2)
    text(p, "12 OZ · WHOLE BEAN", (lx, ly + lh - 40, lw, 24), 14, "#6b5a49", spacing=2)
    gloss(p, body, 60)


def obj_tin(p, cx, base, col, accent, name, sub, w=360, h=420):
    floor_shadow(p, cx, base + 6, w * 1.2)
    x, top = cx - w / 2, base - h
    ry = w * 0.12
    body = QPainterPath()
    body.moveTo(x, top)
    body.lineTo(x, base)
    body.arcTo(QRectF(x, base - ry, w, 2 * ry), 180, 180)
    body.lineTo(x + w, top)
    body.closeSubpath()
    fill(p, body, lin(x, 0, x + w, 0, (0, shade(col, 0.75)), (0.3, shade(col, 1.25)), (1, shade(col, 0.7))))
    fill(p, rrpath(x - 6, top - 8, w + 12, 46, 14), lin(0, top, 0, top + 40, (0, shade(col, 1.3)), (1, shade(col, 0.9))))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(lin(x, 0, x + w, 0, (0, shade(col, 1.1)), (1, shade(col, 0.8))))
    p.drawEllipse(QPointF(cx, top - 6), w / 2 + 6, ry * 0.9)
    lh = h * 0.5
    ly = top + h * 0.28
    fill(p, QPainterPath(), QBrush())
    p.setBrush(QBrush(C("#f4ead8")))
    p.setPen(QPen(C(accent), 4))
    p.drawRect(QRectF(x, ly, w, lh))
    text(p, "FERNHILL", (x, ly + 20, w, 26), 20, accent, bold=True, spacing=6)
    text(p, name, (x + 20, ly + 56, w - 40, lh * 0.5), 32, "#2b1d14", bold=True)
    text(p, sub, (x, ly + lh - 56, w, 30), 17, accent, spacing=2)
    gloss(p, body, 70)


def obj_mug(p, cx, base, col, accent="#fff", w=400, h=380, coffee=True, saucer=False):
    floor_shadow(p, cx, base + 4, w * 1.35)
    x, top = cx - w / 2, base - h
    if saucer:
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(lin(0, base - 30, 0, base + 14, (0, "#f1ece4"), (1, "#cfc5b6")))
        p.drawEllipse(QPointF(cx, base - 6), w * 0.78, 34)
    # handle
    hp = QPainterPath()
    hp.moveTo(x + w - 10, top + h * 0.2)
    hp.cubicTo(x + w + 150, top + h * 0.1, x + w + 150, top + h * 0.85, x + w - 20, top + h * 0.78)
    p.setPen(QPen(shade(col, 0.85), 38, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(hp)
    p.setPen(QPen(shade(col, 1.15), 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawPath(hp)
    body = QPainterPath()
    body.moveTo(x, top)
    body.lineTo(x + 18, base - 40)
    body.quadTo(x + 24, base, x + 80, base)
    body.lineTo(x + w - 80, base)
    body.quadTo(x + w - 24, base, x + w - 18, base - 40)
    body.lineTo(x + w, top)
    body.closeSubpath()
    fill(p, body, lin(x, 0, x + w, 0, (0, shade(col, 0.78)), (0.3, shade(col, 1.18)), (1, shade(col, 0.72))))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(shade(col, 0.6))
    p.drawEllipse(QPointF(cx, top), w / 2, 36)
    if coffee:
        p.setBrush(lin(0, top - 20, 0, top + 30, (0, "#6b4128"), (1, "#3b2314")))
        p.drawEllipse(QPointF(cx, top + 2), w / 2 - 22, 28)
        p.setBrush(C("#ffffff", 50))
        p.drawEllipse(QPointF(cx - w * 0.12, top - 4), w * 0.16, 8)
    else:
        p.setBrush(shade(col, 0.5))
        p.drawEllipse(QPointF(cx, top + 2), w / 2 - 22, 28)
    gloss(p, body, 75)


def obj_kettle(p, cx, base, col, accent="#c9803d", s=1.0):
    floor_shadow(p, cx, base + 4, 560 * s)
    w, h = 300 * s, 270 * s
    x, top = cx - w / 2, base - h - 30 * s
    # base plate
    fill(p, rrpath(cx - 200 * s, base - 40 * s, 400 * s, 40 * s, 14), lin(0, base - 40, 0, base, (0, shade(col, 1.3)), (1, shade(col, 0.6))))
    # spout (gooseneck)
    sp = QPainterPath()
    sp.moveTo(x + w - 40 * s, top + h * 0.7)
    sp.cubicTo(x + w + 150 * s, top + h * 0.7, x + w + 230 * s, top + h * 0.4, x + w + 250 * s, top - 40 * s)
    p.setPen(QPen(shade(col, 0.8), 30 * s, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(sp)
    p.setPen(QPen(shade(col, 1.3), 9 * s, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawPath(sp)
    # handle
    hd = QPainterPath()
    hd.moveTo(x + 30 * s, top + 40 * s)
    hd.cubicTo(x - 150 * s, top - 20 * s, x - 150 * s, top + h * 0.8, x + 20 * s, top + h * 0.8)
    p.setPen(QPen(C(accent), 26 * s, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawPath(hd)
    body = QPainterPath()
    body.moveTo(x + 20 * s, top + 30 * s)
    body.lineTo(x + w - 20 * s, top + 30 * s)
    body.lineTo(x + w, base - 40 * s)
    body.lineTo(x, base - 40 * s)
    body.closeSubpath()
    fill(p, body, lin(x, 0, x + w, 0, (0, shade(col, 0.7)), (0.3, shade(col, 1.25)), (1, shade(col, 0.65))))
    # lid
    fill(p, rrpath(x + 10 * s, top, w - 20 * s, 40 * s, 16), lin(0, top, 0, top + 40, (0, shade(col, 1.3)), (1, shade(col, 0.8))))
    p.setBrush(C(accent))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(QPointF(cx, top - 14 * s), 22 * s, 22 * s)
    # dial
    p.setBrush(QColor("#f4ead8"))
    p.setPen(QPen(C(accent), 5))
    p.drawEllipse(QPointF(cx, top + h * 0.55), 52 * s, 52 * s)
    p.setPen(QPen(C("#2b1d14"), 4))
    p.drawLine(QPointF(cx, top + h * 0.55), QPointF(cx + 28 * s, top + h * 0.55 - 26 * s))
    gloss(p, body, 60)


def obj_dripper(p, cx, base, col, accent="#c9803d"):
    floor_shadow(p, cx, base + 4, 520)
    # carafe-less: cone on a small cup stand
    fill(p, rrpath(cx - 110, base - 150, 220, 150, 18), lin(cx - 110, 0, cx + 110, 0, (0, "#d9d2c6"), (0.4, "#f4efe6"), (1, "#bdb4a5")))
    cone = QPainterPath()
    cone.moveTo(cx - 230, base - 440)
    cone.lineTo(cx + 230, base - 440)
    cone.lineTo(cx + 60, base - 150)
    cone.lineTo(cx - 60, base - 150)
    cone.closeSubpath()
    fill(p, cone, lin(cx - 230, 0, cx + 230, 0, (0, shade(col, 0.78)), (0.3, shade(col, 1.2)), (1, shade(col, 0.7))))
    p.setPen(QPen(C("#000", 28), 4))
    for i in range(-3, 4):
        p.drawLine(QPointF(cx + i * 56, base - 436), QPointF(cx + i * 15, base - 160))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(shade(col, 1.25))
    p.drawEllipse(QPointF(cx, base - 440), 232, 30)
    p.setBrush(shade(col, 0.45))
    p.drawEllipse(QPointF(cx, base - 440), 210, 22)
    fill(p, rrpath(cx + 218, base - 470, 90, 44, 14), QBrush(shade(col, 0.9)))
    gloss(p, cone, 70)


def obj_grinder(p, cx, base, col, accent="#c9803d"):
    floor_shadow(p, cx, base + 4, 440)
    # jar
    jar = rrpath(cx - 110, base - 170, 220, 170, 24)
    fill(p, jar, lin(cx - 110, 0, cx + 110, 0, (0, "#cfd6d8"), (0.35, "#f1f6f7"), (1, "#aab4b8")))
    p.setBrush(C("#4a2e1d", 210))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(cx - 100, base - 90, 200, 82), 18, 18)
    # body
    body = QPainterPath()
    body.moveTo(cx - 110, base - 170)
    body.lineTo(cx - 80, base - 470)
    body.lineTo(cx + 80, base - 470)
    body.lineTo(cx + 110, base - 170)
    body.closeSubpath()
    fill(p, body, lin(cx - 110, 0, cx + 110, 0, (0, shade(col, 0.75)), (0.3, shade(col, 1.2)), (1, shade(col, 0.68))))
    p.setPen(QPen(C(accent), 8))
    p.drawLine(QPointF(cx - 100, base - 250), QPointF(cx + 100, base - 250))
    # crank
    p.setPen(QPen(shade(col, 0.55), 18, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawLine(QPointF(cx, base - 490), QPointF(cx + 230, base - 490))
    p.drawLine(QPointF(cx + 230, base - 490), QPointF(cx + 230, base - 380))
    p.setBrush(C(accent))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(QPointF(cx + 230, base - 370), 30, 30)
    fill(p, rrpath(cx - 90, base - 520, 180, 56, 20), lin(0, base - 520, 0, base - 464, (0, shade(col, 1.3)), (1, shade(col, 0.7))))
    gloss(p, body, 60)


def obj_scale(p, cx, base, col, accent="#c9803d"):
    floor_shadow(p, cx, base + 4, 560)
    top = QPainterPath()
    top.moveTo(cx - 250, base - 120)
    top.lineTo(cx + 250, base - 120)
    top.lineTo(cx + 300, base - 30)
    top.lineTo(cx - 300, base - 30)
    top.closeSubpath()
    fill(p, top, lin(0, base - 120, 0, base - 30, (0, shade(col, 1.35)), (1, shade(col, 0.95))))
    fill(p, rrpath(cx - 300, base - 40, 600, 40, 16), lin(0, base - 40, 0, base, (0, shade(col, 0.8)), (1, shade(col, 0.45))))
    # display
    fill(p, rrpath(cx - 150, base - 24, 300, 18, 8), QBrush(C("#1b1b1b")))
    p.setBrush(C("#1b1b1b"))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(cx - 130, base - 108, 260, 60), 12, 12)
    text(p, "18.0 g  0:32", (cx - 130, base - 104, 260, 52), 28, "#7dff8a", font="Monospace", bold=True)
    p.setBrush(C(accent))
    p.drawEllipse(QPointF(cx - 210, base - 82), 15, 15)
    p.drawEllipse(QPointF(cx + 210, base - 82), 15, 15)


def obj_filters(p, cx, base, col, accent="#c9803d"):
    floor_shadow(p, cx, base + 4, 520)
    w, h = 400, 330
    x, top = cx - w / 2, base - h
    fill(p, rrpath(x, top, w, h, 14), lin(x, 0, x + w, 0, (0, shade(col, 0.85)), (0.4, shade(col, 1.15)), (1, shade(col, 0.78))))
    fill(p, rrpath(x + 40, top + 40, w - 80, 120, 10), QBrush(C("#f4ead8")))
    # window showing filters
    fill(p, rrpath(x + 70, top + 190, w - 140, 80, 10), QBrush(C("#fff", 230)))
    p.setPen(QPen(C("#cdbfa6"), 3))
    for i in range(6):
        p.drawLine(QPointF(x + 90 + i * 40, top + 196), QPointF(x + 90 + i * 40, top + 264))
    text(p, "FERNHILL", (x + 40, top + 52, w - 80, 28), 20, accent, bold=True, spacing=6)
    text(p, "Paper Filters", (x + 40, top + 84, w - 80, 40), 30, "#2b1d14", bold=True)
    text(p, "100 · Size 02", (x + 40, top + 128, w - 80, 24), 15, "#6b5a49", spacing=2)


def obj_press(p, cx, base, col, accent="#2b1d14"):
    floor_shadow(p, cx, base + 4, 520)
    w, h = 260, 430
    x, top = cx - w / 2, base - h
    glass = rrpath(x, top, w, h, 14)
    fill(p, glass, lin(x, 0, x + w, 0, (0, "#c9d9dc"), (0.3, "#eef6f7"), (1, "#a6b8bc")))
    p.setBrush(lin(0, top + 120, 0, base, (0, "#6b4128"), (1, "#3b2314")))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(x + 8, top + 150, w - 16, h - 158), 10, 10)
    # frame
    p.setPen(QPen(C(accent), 22, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawLine(QPointF(x - 6, base - 8), QPointF(x + w + 6, base - 8))
    p.drawLine(QPointF(x - 6, top + 6), QPointF(x + w + 6, top + 6))
    hd = QPainterPath()
    hd.moveTo(x + w + 6, top + 30)
    hd.cubicTo(x + w + 150, top + 30, x + w + 150, base - 60, x + w + 4, base - 40)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.setPen(QPen(C(accent), 26, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawPath(hd)
    # plunger
    p.setPen(QPen(C("#9aa0a4"), 10))
    p.drawLine(QPointF(cx, top - 90), QPointF(cx, top + 150))
    p.setBrush(C(accent))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(QPointF(cx, top - 100), 32, 28)
    gloss(p, glass, 90)


def obj_pitcher(p, cx, base, col, accent="#c9803d"):
    floor_shadow(p, cx, base + 4, 440)
    w, h = 270, 320
    x, top = cx - w / 2, base - h
    hd = QPainterPath()
    hd.moveTo(x + w - 20, top + 60)
    hd.cubicTo(x + w + 130, top + 40, x + w + 130, base - 40, x + w - 30, base - 60)
    p.setPen(QPen(shade(col, 0.8), 30, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(hd)
    body = QPainterPath()
    body.moveTo(x - 30, top)       # spout lip
    body.lineTo(x + w, top)
    body.lineTo(x + w - 40, base)
    body.lineTo(x + 40, base)
    body.closeSubpath()
    fill(p, body, lin(x, 0, x + w, 0, (0, shade(col, 0.7)), (0.35, shade(col, 1.4)), (1, shade(col, 0.65))))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(shade(col, 0.55))
    p.drawEllipse(QPointF(cx - 5, top), w / 2 + 12, 22)
    gloss(p, body, 80)


def obj_canister(p, cx, base, col, accent="#c9803d"):
    floor_shadow(p, cx, base + 4, 440)
    w, h = 300, 380
    x, top = cx - w / 2, base - h
    glass = rrpath(x, top + 40, w, h - 40, 30)
    fill(p, glass, lin(x, 0, x + w, 0, (0, "#c5d3d6"), (0.3, "#eef6f7"), (1, "#a1b2b6")))
    rng = random.Random(7)
    p.save()
    p.setClipPath(glass)
    p.fillRect(QRectF(x, top + 130, w, h - 130), QBrush(C("#4a2e1d", 240)))
    for _ in range(36):
        bean(p, rng.uniform(x + 20, x + w - 20), rng.uniform(top + 150, base - 18), rng.uniform(17, 24), rng.uniform(0, 180))
    p.restore()
    fill(p, rrpath(x + 20, top, w - 40, 56, 14), lin(0, top, 0, top + 56, (0, shade(col, 1.3)), (1, shade(col, 0.7))))
    gloss(p, glass, 90)


def obj_press_cup(p, cx, base, col):
    """Double-wall glass cup."""
    floor_shadow(p, cx, base + 4, 360)
    w, h = 250, 300
    x, top = cx - w / 2, base - h
    body = QPainterPath()
    body.moveTo(x, top); body.lineTo(x + 20, base - 20); body.quadTo(x + 26, base, x + 60, base)
    body.lineTo(x + w - 60, base); body.quadTo(x + w - 26, base, x + w - 20, base - 20); body.lineTo(x + w, top)
    body.closeSubpath()
    fill(p, body, lin(x, 0, x + w, 0, (0, "#cbd9dc"), (0.3, "#f2f8f9"), (1, "#a8b9bd")))
    inner = QPainterPath()
    inner.moveTo(x + 22, top + 40); inner.lineTo(x + 38, base - 42); inner.lineTo(x + w - 38, base - 42); inner.lineTo(x + w - 22, top + 40)
    inner.closeSubpath()
    fill(p, inner, lin(0, top + 40, 0, base, (0, "#7a4a2d"), (1, "#3b2314")))
    gloss(p, body, 100)


def obj_tumbler(p, cx, base, col, accent="#c9803d"):
    floor_shadow(p, cx, base + 4, 380)
    top_w, bot_w, h = 250, 190, 470
    x1, top = cx - top_w / 2, base - h
    body = QPainterPath()
    body.moveTo(x1, top + 70); body.lineTo(cx - bot_w / 2, base)
    body.lineTo(cx + bot_w / 2, base); body.lineTo(x1 + top_w, top + 70)
    body.closeSubpath()
    fill(p, body, lin(x1, 0, x1 + top_w, 0, (0, shade(col, 0.75)), (0.3, shade(col, 1.2)), (1, shade(col, 0.68))))
    fill(p, rrpath(x1 - 8, top + 20, top_w + 16, 60, 18), lin(0, top + 20, 0, top + 80, (0, "#3a3a3a"), (1, "#151515")))
    fill(p, rrpath(cx - 70, top, 140, 34, 14), QBrush(C("#262626")))
    p.setBrush(C(accent)); p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(x1 + 14, top + 250, top_w - 28 - 40, 56), 10, 10)
    text(p, "FERNHILL", (x1 + 14, top + 258, top_w - 68, 40), 22, "#fff", bold=True, spacing=5)
    gloss(p, body, 70)


def obj_enamel(p, cx, base, col):
    floor_shadow(p, cx, base + 4, 440)
    w, h = 340, 280
    x, top = cx - w / 2, base - h
    hd = QPainterPath()
    hd.moveTo(x + w - 6, top + 40)
    hd.cubicTo(x + w + 120, top + 30, x + w + 120, base - 50, x + w - 10, base - 50)
    p.setPen(QPen(C("#2b2b2b"), 30, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(hd)
    body = rrpath(x, top, w, h, 28)
    fill(p, body, lin(x, 0, x + w, 0, (0, shade(col, 0.8)), (0.3, shade(col, 1.18)), (1, shade(col, 0.75))))
    p.setPen(QPen(C("#2b2b2b"), 12)); p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawLine(QPointF(x + 4, top + 4), QPointF(x + w - 4, top + 4))
    text(p, "FERNHILL", (x, top + 100, w, 50), 34, "#2b2b2b", bold=True, spacing=7)
    text(p, "COFFEE ROASTERS", (x, top + 150, w, 30), 17, "#2b2b2b", spacing=4)
    gloss(p, body, 80)


def obj_tote(p, cx, base, col, accent="#2b1d14"):
    floor_shadow(p, cx, base + 4, 520)
    w, h = 420, 460
    x, top = cx - w / 2, base - h
    for dx in (-110, 110):
        st = QPainterPath()
        st.moveTo(cx + dx - 40, top + 4); st.cubicTo(cx + dx - 40, top - 230, cx + dx + 40, top - 230, cx + dx + 40, top + 4)
        p.setPen(QPen(shade(col, 0.82), 20, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush); p.drawPath(st)
    body = QPainterPath()
    body.moveTo(x, top); body.lineTo(x + w, top); body.lineTo(x + w - 14, base); body.lineTo(x + 14, base); body.closeSubpath()
    fill(p, body, lin(x, 0, x + w, 0, (0, shade(col, 0.88)), (0.4, shade(col, 1.08)), (1, shade(col, 0.82))))
    p.setPen(QPen(C(accent, 200), 3)); 
    for i in range(0, w, 14):
        p.drawLine(QPointF(x + i, top), QPointF(x + i, top + 2))
    cxl, cyl = cx, top + h * 0.5
    p.setPen(QPen(C(accent), 8)); p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(QPointF(cxl, cyl), 96, 96)
    text(p, "FERN\nHILL", (cxl - 80, cyl - 70, 160, 140), 38, accent, bold=True, spacing=6)
    gloss(p, body, 40)


def obj_apron(p, cx, base, col, accent="#c9803d"):
    floor_shadow(p, cx, base + 4, 480)
    body = QPainterPath()
    body.moveTo(cx - 150, base - 560)
    body.lineTo(cx + 150, base - 560)
    body.lineTo(cx + 130, base - 400)
    body.lineTo(cx + 250, base - 330)
    body.lineTo(cx + 230, base)
    body.lineTo(cx - 230, base)
    body.lineTo(cx - 250, base - 330)
    body.lineTo(cx - 130, base - 400)
    body.closeSubpath()
    p.setPen(QPen(shade(col, 0.8), 18, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)); p.setBrush(Qt.BrushStyle.NoBrush)
    neck = QPainterPath(); neck.moveTo(cx - 140, base - 556); neck.cubicTo(cx - 100, base - 700, cx + 100, base - 700, cx + 140, base - 556)
    p.drawPath(neck)
    fill(p, body, lin(cx - 250, 0, cx + 250, 0, (0, shade(col, 0.82)), (0.5, shade(col, 1.12)), (1, shade(col, 0.78))))
    fill(p, rrpath(cx - 130, base - 250, 260, 150, 8), QBrush(shade(col, 0.88)), QPen(shade(col, 0.6), 3, Qt.PenStyle.DashLine))
    text(p, "FERNHILL", (cx - 130, base - 460, 260, 40), 28, C("#f4ead8").name(), bold=True, spacing=6)


def obj_cap(p, cx, base, col, accent="#f4ead8"):
    floor_shadow(p, cx, base + 4, 500)
    dome = QPainterPath()
    dome.moveTo(cx - 210, base - 90)
    dome.cubicTo(cx - 210, base - 380, cx + 210, base - 380, cx + 210, base - 90)
    dome.closeSubpath()
    fill(p, dome, lin(cx - 210, 0, cx + 210, 0, (0, shade(col, 0.78)), (0.35, shade(col, 1.18)), (1, shade(col, 0.72))))
    brim = QPainterPath()
    brim.moveTo(cx - 200, base - 100)
    brim.cubicTo(cx - 100, base - 40, cx + 330, base - 20, cx + 360, base - 80)
    brim.cubicTo(cx + 330, base - 120, cx + 100, base - 130, cx + 200, base - 100)
    brim.closeSubpath()
    fill(p, brim, lin(0, base - 130, 0, base - 20, (0, shade(col, 1.0)), (1, shade(col, 0.6))))
    p.setBrush(C(accent)); p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(QPointF(cx, base - 250), 46, 46)
    text(p, "F", (cx - 40, base - 290, 80, 80), 52, col, bold=True)
    gloss(p, dome, 60)


def obj_gift(p, cx, base, col, accent="#c9803d", ribbon="#f4ead8"):
    floor_shadow(p, cx, base + 4, 600)
    w, h = 440, 280
    x, top = cx - w / 2, base - h
    fill(p, rrpath(x, top, w, h, 10), lin(x, 0, x + w, 0, (0, shade(col, 0.85)), (0.5, shade(col, 1.1)), (1, shade(col, 0.78))))
    fill(p, rrpath(x - 14, top - 62, w + 28, 80, 10), lin(0, top - 62, 0, top + 18, (0, shade(col, 1.2)), (1, shade(col, 0.82))))
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(C(ribbon))
    p.drawRect(QRectF(cx - 26, top - 62, 52, h + 62))
    for sgn in (-1, 1):
        bow = QPainterPath()
        bow.moveTo(cx, top - 66)
        bow.cubicTo(cx + sgn * 130, top - 200, cx + sgn * 150, top - 70, cx, top - 62)
        fill(p, bow, QBrush(C(ribbon)), QPen(shade(ribbon, 0.8), 3))
    p.setBrush(shade(ribbon, 0.9)); p.drawEllipse(QPointF(cx, top - 66), 24, 20)
    text(p, "FERNHILL", (x, top + 120, w, 40), 28, "#f4ead8", bold=True, spacing=8)


def obj_card(p, cx, base, col, accent="#c9803d"):
    floor_shadow(p, cx, base + 4, 520)
    p.save(); p.translate(cx, base - 220); p.rotate(-6)
    w, h = 560, 340
    card = rrpath(-w / 2, -h / 2, w, h, 26)
    fill(p, card, lin(-w / 2, -h / 2, w / 2, h / 2, (0, shade(col, 1.2)), (1, shade(col, 0.72))))
    text(p, "FERNHILL", (-w / 2 + 40, -h / 2 + 34, 300, 30), 22, "#f4ead8", bold=True, spacing=7, align=Qt.AlignmentFlag.AlignLeft)
    text(p, "Coffee Club", (-w / 2 + 40, -40, w - 80, 70), 62, "#f4ead8", bold=True, align=Qt.AlignmentFlag.AlignLeft)
    text(p, "FRESH ROASTED · EVERY MONTH", (-w / 2 + 40, h / 2 - 70, w - 80, 26), 16, accent, spacing=3, align=Qt.AlignmentFlag.AlignLeft)
    for i in range(3):
        bean(p, w / 2 - 90 + (i % 2) * 36, -h / 2 + 80 + i * 40, 22, 30 + i * 40, "#f4ead8")
    p.restore()


OBJECTS = {
    "bag": obj_bag, "tin": obj_tin, "mug": obj_mug, "kettle": obj_kettle, "dripper": obj_dripper,
    "grinder": obj_grinder, "scale": obj_scale, "filters": obj_filters, "press": obj_press,
    "pitcher": obj_pitcher, "canister": obj_canister, "glasscup": obj_press_cup, "tumbler": obj_tumbler,
    "enamel": obj_enamel, "tote": obj_tote, "apron": obj_apron, "cap": obj_cap, "gift": obj_gift, "card": obj_card,
}
