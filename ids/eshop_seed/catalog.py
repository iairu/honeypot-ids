"""Fernhill Coffee Roasters -- the demo store's catalog (single source of truth).

build_assets.py renders every product's images from this and writes catalog.json,
which scripts/seed_storefront_content.php loads. Everything here is invented:
the brand, the farms, the people who "reviewed" the products."""
from __future__ import annotations

import random

BRAND = "Fernhill Coffee Roasters"
TAGLINE = "Small-batch coffee & brewing gear, roasted fresh in Portland, Oregon"

CATEGORIES = [
    ("coffee", "Coffee Beans", "Roasted in small batches every Monday and Thursday, shipped within 24 hours.", "#8a5a3c"),
    ("brewing-gear", "Brewing Gear", "The tools we use in our own cafe, tested daily and built to last.", "#2f5d3a"),
    ("drinkware", "Drinkware", "Mugs, cups and tumblers that make the first sip of the day better.", "#b4532a"),
    ("apparel-merch", "Apparel & Merch", "Wear it, carry it, tie it on. Made with people who make coffee.", "#3d4f6b"),
    ("gifts-subscriptions", "Gifts & Subscriptions", "Curated sets and the monthly Coffee Club for anyone who loves a good cup.", "#7a3b4a"),
]

# ---- coffees -------------------------------------------------------------
# slug, name, origin line, region, farm/coop, altitude, process, roast, notes, price12, price2lb, bag colour, badge
COFFEES = [
    ("ethiopia-guji-natural", "Ethiopia Guji Natural", "Ethiopia · Guji", "Guji Zone, Oromia", "Shakiso smallholders", "2,100 m",
     "Natural, dried on raised beds", "Light", ["Blueberry", "Jasmine", "Wild honey"], 19.00, 62.00, "#4b3a7a", "new", 5),
    ("colombia-huila-washed", "Colombia Huila", "Colombia · Huila", "Pitalito, Huila", "Asociación Los Pinos", "1,750 m",
     "Washed, patio dried", "Medium", ["Caramel", "Red apple", "Cacao nib"], 17.50, 57.00, "#a5532b", "", 4),
    ("guatemala-antigua", "Guatemala Antigua", "Guatemala · Antigua", "Antigua Valley", "Finca El Injerto cooperative", "1,600 m",
     "Washed, sun dried", "Medium-dark", ["Dark chocolate", "Orange zest", "Toasted almond"], 17.00, 55.00, "#7a3b3b", "", 4),
    ("kenya-nyeri-aa", "Kenya Nyeri AA", "Kenya · Nyeri", "Nyeri County", "Gaikundo factory", "1,850 m",
     "Washed, double fermented", "Light", ["Blackcurrant", "Grapefruit", "Brown sugar"], 21.00, 69.00, "#b8423a", "new", 5),
    ("sumatra-mandheling", "Sumatra Mandheling", "Sumatra · Lintong", "Lake Toba highlands", "Permata Gayo growers", "1,400 m",
     "Wet-hulled", "Dark", ["Cedar", "Dark cocoa", "Molasses"], 17.50, 57.00, "#2f3d2f", "", 4),
    ("fernhill-house-blend", "Fernhill House Blend", "Brazil · Colombia · Guatemala", "Three-origin blend", "Our own recipe since 2014", "1,100–1,750 m",
     "Washed and natural", "Medium", ["Toffee", "Hazelnut", "Milk chocolate"], 15.50, 50.00, "#3d5a45", "bestseller", 5),
    ("sunrise-espresso-blend", "Sunrise Espresso", "Brazil · Ethiopia", "Two-origin blend", "Built for the espresso machine", "1,000–2,000 m",
     "Natural and washed", "Medium-dark", ["Dark cherry", "Praline", "Cocoa"], 16.50, 54.00, "#c78a2e", "bestseller", 5),
    ("swiss-water-decaf-colombia", "Decaf Colombia", "Colombia · Cauca", "Cauca Department", "Swiss Water Process, 99.9% caffeine free", "1,800 m",
     "Washed, Swiss Water decaffeinated", "Medium", ["Brown sugar", "Cherry", "Almond"], 18.00, 59.00, "#5e6b73", "", 4),
]

GRINDS = ["Whole bean", "Drip / auto", "Pour-over", "French press", "Espresso", "Moka pot"]

REV_COFFEE = [
    ("Smooth and bright. Tastes just like the description, which almost never happens.", 5),
    ("Fresh roast date was only three days before it landed on my doorstep. Blooms beautifully.", 5),
    ("My go-to for the morning pour-over. Sweet, clean finish, no bitterness.", 5),
    ("Good coffee, a little more acidic than I normally like, but dialing the grind finer fixed it.", 4),
    ("Subscribed after the first bag. The whole house drinks this now.", 5),
    ("Great flavour, packaging is solid and the one-way valve actually works.", 4),
    ("Better than the local cafe. I'm slightly annoyed at how good it is.", 5),
    ("Lovely aroma the second I cut the bag open. Easy to brew, forgiving.", 5),
]
REV_GEAR = [
    ("Feels premium and works exactly as advertised. Wish I'd bought it sooner.", 5),
    ("Solid build quality. Easy to clean and it looks great on the counter.", 5),
    ("Does the job well. Instructions were a bit thin but figured it out in a minute.", 4),
    ("Bought it as a gift and I'm already ordering a second one for myself.", 5),
    ("Heavier than expected in a good way. Nothing rattles or wobbles.", 4),
    ("Great value for the quality. Shipping was fast, packaging was thoughtful.", 5),
]
REV_WEAR = [
    ("Fits true to size and the fabric is thick without being stiff.", 5),
    ("Washed it three times already and the print hasn't faded at all.", 5),
    ("Really nice quality for the price. Gets compliments at the farmers market.", 4),
]
NAMES = [("Maya R.", "Seattle, WA"), ("Daniel K.", "Austin, TX"), ("Priya S.", "Chicago, IL"),
         ("Tom H.", "Denver, CO"), ("Elena V.", "Brooklyn, NY"), ("Marcus L.", "Atlanta, GA"),
         ("Hannah B.", "Minneapolis, MN"), ("Jorge P.", "San Diego, CA"), ("Chloe W.", "Boston, MA"),
         ("Ben A.", "Portland, OR"), ("Sofia M.", "Miami, FL"), ("Liam O.", "Nashville, TN"),
         ("Aisha T.", "Philadelphia, PA"), ("Noah F.", "Salt Lake City, UT"), ("Grace D.", "Madison, WI")]


def _coffee_long(c):
    slug, name, origin, region, farm, alt, proc, roast, notes, *_ = c
    return (
        f"<p>{name} comes from {region}, grown by {farm} at {alt}. The cherries are {proc.lower()}, which "
        f"is where the {notes[0].lower()} and {notes[1].lower()} in the cup come from.</p>"
        f"<p>We roast it to a <strong>{roast.lower()}</strong> profile in 12 kg batches on our Probat drum roaster, "
        f"cupping every batch before it ships. Expect {notes[0].lower()}, {notes[1].lower()} and a "
        f"finish of {notes[2].lower()}.</p>"
        "<p>Each bag is packed in a recyclable, one-way-valve pouch the day it is roasted. For the best cup, "
        "brew within four weeks of the roast date printed on the label.</p>")


def _reviews(rng, pool, n, base_day):
    out = []
    for i in range(n):
        txt, stars = pool[(i * 3 + rng.randrange(len(pool))) % len(pool)]
        name, city = NAMES[(i * 5 + rng.randrange(len(NAMES))) % len(NAMES)]
        out.append({"author": name, "city": city, "rating": stars, "text": txt,
                    "date": f"2026-0{1 + (base_day + i * 2) % 9}-{10 + (base_day * 3 + i * 7) % 18:02d}"})
    return out


def build():
    rng = random.Random(2026)
    products = []

    for i, c in enumerate(COFFEES):
        slug, name, origin, region, farm, alt, proc, roast, notes, p12, p2, col, badge, rating = c
        n_rev = 6 if badge == "bestseller" else (4 if i % 2 else 3)
        products.append(dict(
            slug=slug, name=name, category="coffee", type="variable", sku=f"FH-{slug[:3].upper()}-{100 + i}",
            price=p12, bag_prices={"12 oz": p12, "2 lb": p2}, grinds=GRINDS,
            short=(f"<p><strong>{', '.join(notes)}.</strong> {roast} roast from {origin}. "
                   "Roasted to order and shipped within 24 hours.</p>"),
            long=_coffee_long(c), obj="bag", bg=["#efe6d6", "#e8e0d2", "#ece3d3"][i % 3], col=col, accent="#6b3f1d" if i % 2 else "#2f5d3a",
            label=name.replace("Fernhill ", "").replace(" Blend", ""), sub=origin.split(" · ")[0].upper(),
            attrs={"Origin": origin, "Roast": roast, "Process": proc, "Altitude": alt, "Tasting notes": ", ".join(notes)},
            weight=0.34, dims=[9, 5, 3], stock=40 + i * 7, tags=["coffee", roast.lower().replace("-", " ")], featured=badge in ("bestseller", "new") or i == 1,
            badge=badge, brew=("pour-over: 18 g coffee, 300 g water at 94 °C, 2:45 total. Espresso: 18 g in, 38 g out, 28 s. "
                               "French press: 1:15 ratio, 4 minute steep, press slowly."),
            reviews=_reviews(rng, REV_COFFEE, n_rev, i + 1), sold=300 - i * 22))

    G = []

    def add(**k):
        k.setdefault("type", "simple")
        k.setdefault("reviews", [])
        k.setdefault("tags", [])
        k.setdefault("featured", False)
        k.setdefault("badge", "")
        k.setdefault("stock", 24)
        k.setdefault("weight", 0.6)
        k.setdefault("dims", [8, 8, 8])
        k.setdefault("attrs", {})
        k.setdefault("sold", 40)
        k.setdefault("accent", "#c9803d")
        G.append(k)

    add(slug="gooseneck-electric-kettle", name="Gooseneck Electric Kettle 0.9 L", category="brewing-gear", sku="FH-KET-200",
        price=79.0, sale=69.0, obj="kettle", col="#2b2b2b", bg="#e6e1d8", featured=True, badge="bestseller", weight=1.4, dims=[26, 20, 24],
        short="<p>Variable-temperature gooseneck kettle with a precise pour spout and a 60-minute hold function.</p>",
        long=("<p>The kettle we use behind our own bar. A counterbalanced gooseneck spout gives you the slow, steady stream "
              "pour-over demands, and the temperature is adjustable from 140 °F to 212 °F in one-degree steps.</p>"
              "<p>Stainless interior, matte powder-coated shell, auto shut-off and boil-dry protection. 1200 W. Cord stores underneath.</p>"),
        attrs={"Capacity": "0.9 L", "Power": "1200 W", "Material": "Stainless steel", "Warranty": "2 years"},
        reviews=_reviews(rng, REV_GEAR, 6, 2), sold=210)
    add(slug="ceramic-pour-over-dripper", name="Ceramic Pour-Over Dripper", category="brewing-gear", sku="FH-DRP-210", price=28.0,
        obj="dripper", col="#e9e1d1", bg="#dfe6dc", accent="#2f5d3a", weight=0.5, dims=[14, 14, 12], featured=True,
        short="<p>Spiral-ribbed ceramic cone, size 02. Brews one to two cups with a clean, sweet extraction.</p>",
        long="<p>A classic cone with a single large hole and spiral ribs for fast, even flow. Glazed ceramic holds heat and goes in the dishwasher. Fits most mugs and carafes. Works with size 02 cone filters.</p>",
        attrs={"Size": "02 (1–4 cups)", "Material": "Glazed ceramic"}, reviews=_reviews(rng, REV_GEAR, 4, 3), sold=180)
    add(slug="hand-burr-coffee-grinder", name="Hand Burr Coffee Grinder", category="brewing-gear", sku="FH-GRN-220", price=89.0,
        obj="grinder", col="#3b3b3b", bg="#e8e2d6", weight=0.9, dims=[7, 7, 21], featured=True, badge="new",
        short="<p>Stainless conical burrs, 40 click settings and a 30 g bean hopper. Quiet, consistent, travels anywhere.</p>",
        long="<p>Hand grinding gives you cafe-level consistency without a $300 electric grinder. The 38 mm stainless burrs are adjustable from fine espresso to coarse cold brew, and the aluminum body is anodised for a lifetime of scuffs.</p><p>Disassembles without tools for cleaning. Includes a glass catch jar.</p>",
        attrs={"Burrs": "38 mm conical, stainless", "Capacity": "30 g", "Settings": "40 clicks"}, reviews=_reviews(rng, REV_GEAR, 5, 4), sold=150)
    add(slug="digital-brew-scale", name="Digital Brew Scale with Timer", category="brewing-gear", sku="FH-SCL-230", price=49.0,
        obj="scale", col="#2e2e2e", bg="#e4ded2", weight=0.7, dims=[17, 13, 3],
        short="<p>0.1 g resolution up to 2 kg, with a built-in brew timer and a water-resistant surface.</p>",
        long="<p>The single biggest upgrade to a home brew routine is weighing your coffee and water. This scale reads to 0.1 g, auto-tares, and starts its timer the moment you start pouring. USB-C rechargeable, 40 hours per charge.</p>",
        attrs={"Capacity": "2 kg", "Resolution": "0.1 g"}, reviews=_reviews(rng, REV_GEAR, 3, 5), sold=120)
    add(slug="paper-filters-size-02", name="Paper Filters, Size 02 (100 ct)", category="brewing-gear", sku="FH-FLT-240", price=9.0,
        obj="filters", col="#d8c7a4", bg="#e8e1d4", weight=0.15, dims=[12, 9, 9], stock=200,
        short="<p>Unbleached, oxygen-cleaned cone filters. A clean cup with no papery aftertaste.</p>",
        long="<p>100 unbleached cone filters for size 02 drippers. Rinse before brewing. Compostable.</p>",
        reviews=_reviews(rng, REV_GEAR, 3, 6), sold=500)
    add(slug="glass-french-press", name="Glass French Press 34 oz", category="brewing-gear", sku="FH-FRP-250", price=42.0,
        obj="press", col="#2b2b2b", bg="#e2e6e0", weight=0.9, dims=[12, 10, 24],
        short="<p>Borosilicate glass beaker, double-mesh stainless filter and a steel frame. Rich, full-bodied coffee.</p>",
        long="<p>The simplest way to brew a full, heavy-bodied cup. Heat-resistant borosilicate glass, a dual-screen stainless plunger that keeps grounds out of your cup, and a frame that protects against knocks. Makes 4 cups.</p>",
        attrs={"Capacity": "34 oz (1 L)"}, reviews=_reviews(rng, REV_GEAR, 4, 7), sold=130)
    add(slug="stainless-milk-pitcher", name="Stainless Milk Pitcher 12 oz", category="brewing-gear", sku="FH-PIT-260", price=24.0,
        obj="pitcher", col="#c5c9cc", bg="#e8e3d9", weight=0.25, dims=[11, 8, 9],
        short="<p>Pointed spout for latte art, thermal-grade 18/8 stainless, 12 oz capacity.</p>",
        long="<p>A sharp spout and a perfectly weighted handle make microfoam pours controllable. Dishwasher safe.</p>", sold=85)
    add(slug="glass-bean-canister", name="Glass Bean Canister", category="brewing-gear", sku="FH-CAN-270", price=22.0,
        obj="canister", col="#2b2b2b", bg="#e5dfd3", weight=0.8, dims=[11, 11, 17],
        short="<p>Airtight seal with a stainless lid. Holds a full 12 oz bag plus a little more.</p>",
        long="<p>Store beans away from light and air. Silicone gasket, stainless lid and a date dial so you always know how fresh they are.</p>", sold=70)

    add(slug="stoneware-mug", name="Stoneware Mug", category="drinkware", sku="FH-MUG-300", price=22.0, obj="mug", col="#6b7d58", bg="#e7e0d0", weight=0.45, dims=[12, 9, 9],
        type="variable", variants={"Colour": {"Moss": "#6b7d58", "Clay": "#b4663d", "Oat": "#d9cdb4"}}, featured=True, badge="bestseller",
        short="<p>Hand-glazed 12 oz stoneware with a thumb-rest handle. Each one is slightly different.</p>",
        long="<p>Thrown and glazed in small batches by a family pottery in North Carolina. Holds 12 oz, microwave and dishwasher safe.</p>",
        attrs={"Capacity": "12 oz", "Material": "Stoneware"}, reviews=_reviews(rng, REV_GEAR, 6, 8), sold=260)
    add(slug="double-wall-glass-cups", name="Double-Wall Glass Cups (Set of 2)", category="drinkware", sku="FH-GLS-310", price=26.0,
        obj="glasscup", col="#d9e6e8", bg="#e3e8e2", weight=0.5, dims=[9, 9, 9],
        short="<p>Insulated borosilicate glass that keeps drinks hot and your hands cool.</p>",
        long="<p>A set of two 8 oz double-wall cups. Great for espresso, cortado or tea, and they look lovely with a layered latte.</p>", sold=95)
    add(slug="insulated-travel-tumbler", name="Insulated Travel Tumbler 16 oz", category="drinkware", sku="FH-TMB-320", price=34.0, sale=29.0,
        obj="tumbler", col="#2f5d3a", bg="#e6e1d7", weight=0.4, dims=[8, 8, 20], featured=True,
        short="<p>Vacuum-insulated steel. Hot for 8 hours, cold for 24, with a leak-resistant sip lid.</p>",
        long="<p>Double-wall 18/8 stainless with a powder-coat finish. Fits most cup holders. Hand wash recommended.</p>", reviews=_reviews(rng, REV_GEAR, 4, 9), sold=160)
    add(slug="enamel-camp-mug", name="Enamel Camp Mug", category="drinkware", sku="FH-ENM-330", price=18.0, obj="enamel", col="#e9e3d6", bg="#dfe5e6",
        weight=0.25, dims=[10, 8, 8], short="<p>Speckled enamel on steel with a rolled rim. Built for campfires and kitchens.</p>",
        long="<p>A classic 12 oz enamel mug with the Fernhill wordmark. Dishwasher safe, practically unbreakable.</p>", sold=110)

    add(slug="fernhill-canvas-tote", name="Fernhill Canvas Tote", category="apparel-merch", sku="FH-TOT-400", price=24.0, obj="tote", col="#e5d9bf", bg="#e8e1d3",
        accent="#2f5d3a", weight=0.3, short="<p>Heavy 12 oz cotton canvas with reinforced handles. Holds two bags of beans and the farmers-market haul.</p>",
        long="<p>Screen-printed by hand in Portland. 15 x 16 inches with a 24-inch shoulder strap.</p>", reviews=_reviews(rng, REV_WEAR, 3, 10), sold=140)
    add(slug="barista-apron", name="Barista Apron", category="apparel-merch", sku="FH-APR-410", price=48.0, obj="apron", col="#3a4a3d", bg="#e6e0d3",
        weight=0.5, short="<p>Waxed canvas with leather straps, a cross-back fit and a split pocket. The one our baristas wear.</p>",
        long="<p>Waxed 14 oz canvas that sheds water and gets better with age. Adjustable leather cross-back straps, one size fits most.</p>", reviews=_reviews(rng, REV_WEAR, 3, 11), sold=60)
    add(slug="logo-cap", name="Fernhill Logo Cap", category="apparel-merch", sku="FH-CAP-420", price=26.0, obj="cap", col="#b4663d", bg="#e5ddcf",
        weight=0.15, short="<p>Six-panel organic cotton twill with an embroidered F. Adjustable brass buckle.</p>",
        long="<p>Soft, unstructured and broken-in from day one. One size fits most.</p>", sold=75)

    add(slug="coffee-lover-gift-box", name="Coffee Lover Gift Box", category="gifts-subscriptions", sku="FH-GFT-500", price=64.0, obj="gift", col="#3d5a45", bg="#ede4d3",
        featured=True, badge="new", weight=1.4, dims=[28, 22, 12],
        short="<p>Two 12 oz bags (our choice of seasonal beans), a stoneware mug and a handwritten card, in a reusable kraft box.</p>",
        long="<p>The easiest gift for anyone who drinks coffee. Includes two freshly roasted 12 oz bags, a Fernhill stoneware mug and a handwritten card. Free gift wrap on request at checkout.</p>",
        reviews=_reviews(rng, REV_GEAR, 4, 12), sold=90)
    add(slug="pour-over-starter-kit", name="Pour-Over Starter Kit", category="gifts-subscriptions", sku="FH-KIT-510", price=119.0, sale=105.0, obj="dripper",
        col="#f0e9da", bg="#dde6dd", accent="#2f5d3a", weight=2.2, dims=[30, 24, 16], featured=True,
        short="<p>Everything for your first great cup: dripper, filters, scale, gooseneck kettle and a bag of House Blend.</p>",
        long="<p>Skip the guesswork. Includes a ceramic dripper, 100 filters, a digital scale, a gooseneck kettle and a 12 oz bag of Fernhill House Blend, plus a brewing card with our recipe.</p>",
        reviews=_reviews(rng, REV_GEAR, 5, 13), sold=70)
    add(slug="coffee-club-subscription", name="Coffee Club Subscription", category="gifts-subscriptions", sku="FH-SUB-520", price=18.0, obj="card",
        col="#2f5d3a", bg="#e9e2d3", type="variable", variants={"Delivery": {"Every 2 weeks": "", "Every month": "", "Every 2 months": ""}},
        short="<p>Fresh-roasted coffee at your door on your schedule. Pause, skip or cancel anytime.</p>",
        long="<p>Pick a roast style, a grind and a schedule. Each shipment is roasted the week it ships and costs less than buying a bag. Free shipping, always.</p>",
        reviews=_reviews(rng, REV_COFFEE, 4, 14), sold=190, badge="bestseller")
    products += G
    return products


def avg(p):
    r = p.get("reviews") or []
    return round(sum(x["rating"] for x in r) / len(r), 2) if r else 0
