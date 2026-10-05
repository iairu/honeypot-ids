#!/usr/bin/env python3
"""Render the Fernhill storefront's images and catalog.json.

    QT_QPA_PLATFORM=offscreen python3 build_assets.py     # needs PyQt6

Outputs (all committed, so a fresh clone never needs to run this):
    products/<slug>.jpg, products/<slug>-2.jpg   product gallery images
    site/*.jpg|png                              hero, category tiles, journal, logo, icon
    catalog.json                                read by scripts/seed_storefront_content.php
"""
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QFontDatabase, QGuiApplication, QImage, QPainter, QPainterPath, QPen

import art
import catalog
from art import C, OBJECTS, backdrop, bean, canvas, floor_shadow, lin, scatter_beans, shade, text

HERE = os.path.dirname(os.path.abspath(__file__))
FONT = os.path.join(HERE, "..", "..", "dashboard", "resources", "fonts", "LibreBaskerville[wght].ttf")


OBJ_SCALE = {"bag": 1.18, "mug": 1.3, "kettle": 0.98, "dripper": 1.3, "grinder": 1.15, "scale": 1.55, "filters": 1.5,
             "press": 1.2, "pitcher": 1.5, "canister": 1.35, "glasscup": 1.75, "tumbler": 1.2, "enamel": 1.4,
             "tote": 1.15, "apron": 1.0, "cap": 1.5, "gift": 1.25, "card": 1.35}


def draw_object(p, p_def, cx, base, scale=1.0):
    scale *= OBJ_SCALE.get(p_def["obj"], 1.0)
    fn = OBJECTS[p_def["obj"]]
    p.save()
    p.translate(cx, base)
    p.scale(scale, scale)
    p.translate(-cx, -base)
    kw = {}
    if p_def["obj"] == "bag":
        fn(p, cx, base, p_def["col"], p_def["accent"], p_def["label"], p_def["sub"])
    elif p_def["obj"] in ("tin",):
        fn(p, cx, base, p_def["col"], p_def["accent"], p_def["label"], p_def["sub"])
    elif p_def["obj"] in ("mug", "glasscup", "enamel", "canister"):
        fn(p, cx, base, p_def["col"])
    else:
        fn(p, cx, base, p_def["col"], p_def.get("accent", "#c9803d")) if p_def["obj"] not in ("press_cup",) else fn(p, cx, base, p_def["col"])
    p.restore()


def product_image(p_def, variant, path):
    rng = random.Random(hash(p_def["slug"]) & 0xffff)
    img, p = canvas()
    if variant == 0:
        backdrop(p, p_def["bg"])
        draw_object(p, p_def, 500, 830)
        if p_def["obj"] in ("bag", "tin") or rng.random() < 0.5:
            scatter_beans(p, rng, 7, (120, 780, 880, 900), avoid=(300, 700, 700, 840))
    else:
        warm = ["#c9b79a", "#b9c3b0", "#d6c3ae", "#cbb59b"][rng.randrange(4)]
        backdrop(p, warm, floor=0.55)
        # wooden table edge
        p.fillRect(0, 640, 1000, 360, lin(0, 640, 0, 1000, (0, "#9a6f4a"), (1, "#7a5436")))
        p.setPen(QPen(C("#000", 25), 2))
        for y in range(670, 1000, 34):
            p.drawLine(0, y, 1000, y)
        scatter_beans(p, rng, 16, (60, 700, 940, 960), avoid=(300, 700, 700, 900))
        draw_object(p, p_def, 520, 880, 0.85)
    p.end()
    img.save(path, "JPG", 90)


def cat_image(slug, objs, bg, path, w=1200, h=800):
    rng = random.Random(slug)
    img, p = canvas(w, h)
    backdrop(p, bg, w, h, floor=0.7)
    for (o, cx, base, s) in objs:
        p.save()
        p.translate(cx, base); p.scale(s, s); p.translate(-cx, -base)
        OBJECTS[o[0]](p, cx, base, *o[1:])
        p.restore()
    p.end()
    img.save(path, "JPG", 90)


def logo(path, dark, w=720, h=180):
    img = QImage(w, h, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)
    ink = "#2b1d14" if dark else "#f4ead8"
    green = "#2f5d3a" if dark else "#9fc9a1"
    # fern/leaf mark
    p.save(); p.translate(90, 90)
    p.setPen(QPen(C(green), 7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)); p.setBrush(Qt.BrushStyle.NoBrush)
    stem = QPainterPath(); stem.moveTo(0, 64); stem.cubicTo(-8, 20, 6, -20, 0, -64); p.drawPath(stem)
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(C(green))
    for i in range(6):
        y = 50 - i * 21; ln = 38 - i * 4
        for sgn in (-1, 1):
            lf = QPainterPath(); lf.moveTo(0, y); lf.quadTo(sgn * ln * 0.7, y - 22, sgn * ln, y - 10); lf.quadTo(sgn * ln * 0.55, y + 2, 0, y)
            p.drawPath(lf)
    p.restore()
    art.text(p, "Fernhill", (170, 28, 520, 80), 78, ink, bold=True, align=Qt.AlignmentFlag.AlignLeft, spacing=1)
    art.text(p, "COFFEE ROASTERS", (174, 112, 500, 30), 25, ink, align=Qt.AlignmentFlag.AlignLeft, spacing=8)
    p.end()
    img.save(path, "PNG")


def icon(path, size=512):
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHints(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(C("#2f5d3a")); p.drawRoundedRect(QRectF(0, 0, size, size), size * 0.22, size * 0.22)
    p.translate(size / 2, size / 2); p.scale(size / 190, size / 190)
    p.setPen(QPen(C("#f4ead8"), 8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)); p.setBrush(Qt.BrushStyle.NoBrush)
    stem = QPainterPath(); stem.moveTo(0, 68); stem.cubicTo(-8, 20, 6, -20, 0, -68); p.drawPath(stem)
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(C("#f4ead8"))
    for i in range(5):
        y = 52 - i * 24; ln = 42 - i * 5
        for sgn in (-1, 1):
            lf = QPainterPath(); lf.moveTo(0, y); lf.quadTo(sgn * ln * 0.7, y - 24, sgn * ln, y - 10); lf.quadTo(sgn * ln * 0.55, y + 2, 0, y); p.drawPath(lf)
    p.end(); img.save(path, "PNG")


def hero(path, w=1920, h=800):
    rng = random.Random(5)
    img, p = canvas(w, h)
    p.fillRect(0, 0, w, h, lin(0, 0, w, h, (0, "#2b1d14"), (0.55, "#3b2a1e"), (1, "#5a3d27")))
    g = art.QRadialGradient(w * 0.74, h * 0.45, w * 0.5)
    g.setColorAt(0, C("#e8b878", 150)); g.setColorAt(1, C("#e8b878", 0))
    p.fillRect(0, 0, w, h, art.QBrush(g))
    # beans scattered across the table at the bottom
    p.fillRect(0, int(h * 0.82), w, int(h * 0.18), lin(0, h * 0.82, 0, h, (0, "#7a5436"), (1, "#4a3220")))
    scatter_beans(p, rng, 90, (w * 0.35, h * 0.82, w, h))
    OBJECTS["bag"](p, 1180, 760, "#3d5a45", "#f4ead8", "House Blend", "BRAZIL · COLOMBIA", 360, 520)
    OBJECTS["mug"](p, 1530, 760, "#d9cdb4", "#fff", 330, 300)
    OBJECTS["dripper"](p, 1760, 770, "#e9e1d1", "#c9803d")
    p.end(); img.save(path, "JPG", 90)


def journal(path, kind, bg, w=1200, h=675):
    rng = random.Random(kind)
    img, p = canvas(w, h)
    backdrop(p, bg, w, h, floor=0.6)
    if kind == "roast":
        scatter_beans(p, rng, 70, (0, h * 0.55, w, h))
        OBJECTS["bag"](p, 600, 640, "#a5532b", "#f4ead8", "Roast Day", "MONDAY", 330, 470)
    elif kind == "guide":
        OBJECTS["dripper"](p, 420, 620, "#e9e1d1", "#2f5d3a")
        OBJECTS["kettle"](p, 860, 620, "#2b2b2b", "#c9803d", 0.8)
        OBJECTS["scale"](p, 640, 640, "#2e2e2e", "#c9803d")
    else:
        OBJECTS["bag"](p, 420, 640, "#4b3a7a", "#f4ead8", "Guji", "ETHIOPIA", 330, 470)
        OBJECTS["mug"](p, 800, 640, "#b4663d", "#fff", 320, 290)
        scatter_beans(p, rng, 24, (0, h * 0.8, w, h))
    p.end(); img.save(path, "JPG", 90)


def main():
    app = QGuiApplication(sys.argv)
    QFontDatabase.addApplicationFont(FONT)
    os.makedirs(f"{HERE}/products", exist_ok=True)
    os.makedirs(f"{HERE}/site", exist_ok=True)
    products = catalog.build()
    only = sys.argv[1:]
    for pr in products:
        if only and pr["slug"] not in only:
            continue
        product_image(pr, 0, f"{HERE}/products/{pr['slug']}.jpg")
        product_image(pr, 1, f"{HERE}/products/{pr['slug']}-2.jpg")
        print("product", pr["slug"], flush=True)
    if not only:
        BAG = lambda c, n, s: ("bag", c, "#f4ead8", n, s, 330, 480)
        cat_image("coffee", [(BAG("#4b3a7a", "Guji", "ETHIOPIA"), 360, 700, 0.95), (BAG("#3d5a45", "House", "BLEND"), 640, 720, 1.0),
                              (BAG("#a5532b", "Huila", "COLOMBIA"), 900, 700, 0.9)], "#ece2d1", f"{HERE}/site/cat-coffee.jpg")
        cat_image("brewing-gear", [(("kettle", "#2b2b2b", "#c9803d", 0.8), 420, 700, 1.0), (("dripper", "#e9e1d1", "#2f5d3a"), 850, 700, 0.95)],
                  "#dfe6dc", f"{HERE}/site/cat-brewing-gear.jpg")
        cat_image("drinkware", [(("mug", "#6b7d58", "#fff", 330, 300), 400, 700, 1.0), (("tumbler", "#2f5d3a", "#c9803d"), 800, 710, 0.9)],
                  "#ece1cf", f"{HERE}/site/cat-drinkware.jpg")
        cat_image("apparel-merch", [(("tote", "#e5d9bf", "#2f5d3a"), 420, 720, 0.85), (("cap", "#b4663d", "#f4ead8"), 850, 720, 0.9)],
                  "#e3e7ee", f"{HERE}/site/cat-apparel-merch.jpg")
        cat_image("gifts-subscriptions", [(("gift", "#3d5a45", "#c9803d", "#f4ead8"), 500, 740, 1.0), (("card", "#2f5d3a", "#c9803d"), 900, 740, 0.7)],
                  "#efe3e4", f"{HERE}/site/cat-gifts-subscriptions.jpg")
        hero(f"{HERE}/site/hero.jpg")
        journal(f"{HERE}/site/journal-roast.jpg", "roast", "#d9c6a8")
        journal(f"{HERE}/site/journal-guide.jpg", "guide", "#dfe6dc")
        journal(f"{HERE}/site/journal-origin.jpg", "origin", "#e8dccb")
        logo(f"{HERE}/site/logo-dark.png", True)
        logo(f"{HERE}/site/logo-light.png", False)
        icon(f"{HERE}/site/icon.png")
    # Note: catalog.json is plain data for the PHP seeder.
    with open(f"{HERE}/catalog.json", "w") as f:
        json.dump({"brand": catalog.BRAND, "tagline": catalog.TAGLINE,
                   "categories": [dict(slug=s, name=n, description=d, color=c) for s, n, d, c in catalog.CATEGORIES],
                   "grinds": catalog.GRINDS,
                   "products": [dict(pr, rating=catalog.avg(pr)) for pr in products]}, f, indent=1)
    print("done")


if __name__ == "__main__":
    main()
