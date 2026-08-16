#!/usr/bin/env python3
"""
gen_parquet_orders.py — nested e-commerce order documents, one column: `message`.

Each row is a single JSON order document. The shape extends the minimal form:

    {"order_id":"ORDER-001","total_amount":99.99,
     "customer":{"id":"CUST-1","country":"United States"},
     "product":{"name":"Laptop Stand","category":"Electronics"}}

Every key in that example is preserved at the same path, so queries written
against the short form keep working. Around them the document adds nested
objects and arrays: pricing breakdown, customer address and tier, product
attributes and ratings, shipping with carrier events[], payment, fulfillment,
and an optional return/refund block.

Internal consistency is enforced, which is what makes the data usable for
teaching rather than just voluminous:

  * total_amount == subtotal - discount + tax + shipping   (to the cent)
  * currency, city, region and carrier all follow from customer.country
  * amount_usd is total_amount converted at the document's own fx_rate
  * JPY and KRW carry no minor units
  * timestamps advance in order: placed -> paid -> shipped -> delivered
  * a return can only exist on a delivered order
  * status distribution shifts with order age (recent orders are still in flight)
  * Q4 carries a seasonal volume and basket-size lift

Usage:
    python3 gen_parquet_orders.py
    python3 gen_parquet_orders.py --rows 2000000 --days 730
    python3 gen_parquet_orders.py --ndjson orders.ndjson
    python3 gen_parquet_orders.py --sample 3          # print docs, write nothing
"""
import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone

import pyarrow as pa
import pyarrow.parquet as pq

# ---------------------------------------------------------------------------
# Markets. (country, weight, currency, fx_per_usd, region_label, cities, carriers)
# ---------------------------------------------------------------------------
MARKETS = [
    ("United States", 30, "USD", 1.00, "state",
     [("Austin", "TX", "78701"), ("Pittsburgh", "PA", "15219"),
      ("Denver", "CO", "80202"), ("Seattle", "WA", "98101"),
      ("Chicago", "IL", "60601"), ("Miami", "FL", "33101")],
     ["UPS", "FedEx", "USPS"]),
    ("Germany", 11, "EUR", 0.92, "state",
     [("Berlin", "BE", "10115"), ("Munich", "BY", "80331"),
      ("Hamburg", "HH", "20095"), ("Cologne", "NW", "50667")],
     ["DHL", "Hermes", "DPD"]),
    ("United Kingdom", 10, "GBP", 0.79, "county",
     [("London", "Greater London", "EC1A"), ("Manchester", "Greater Manchester", "M1"),
      ("Bristol", "Bristol", "BS1"), ("Edinburgh", "Midlothian", "EH1")],
     ["Royal Mail", "DPD", "Evri"]),
    ("Japan", 9, "JPY", 152.0, "prefecture",
     [("Tokyo", "Tokyo", "100-0001"), ("Osaka", "Osaka", "530-0001"),
      ("Nagoya", "Aichi", "450-0002"), ("Fukuoka", "Fukuoka", "810-0001")],
     ["Yamato", "Sagawa", "Japan Post"]),
    ("Canada", 8, "CAD", 1.37, "province",
     [("Toronto", "ON", "M5H"), ("Vancouver", "BC", "V6B"),
      ("Montreal", "QC", "H3B"), ("Calgary", "AB", "T2P")],
     ["Canada Post", "Purolator", "UPS"]),
    ("France", 6, "EUR", 0.92, "region",
     [("Paris", "Ile-de-France", "75001"), ("Lyon", "Auvergne-Rhone-Alpes", "69001"),
      ("Marseille", "Provence-Alpes-Cote d'Azur", "13001")],
     ["Colissimo", "Chronopost", "DPD"]),
    ("Australia", 5, "AUD", 1.52, "state",
     [("Sydney", "NSW", "2000"), ("Melbourne", "VIC", "3000"),
      ("Brisbane", "QLD", "4000"), ("Perth", "WA", "6000")],
     ["Australia Post", "StarTrack", "Aramex"]),
    ("Netherlands", 4, "EUR", 0.92, "province",
     [("Amsterdam", "NH", "1011"), ("Rotterdam", "ZH", "3011"),
      ("Utrecht", "UT", "3511")],
     ["PostNL", "DHL", "DPD"]),
    ("Brazil", 4, "BRL", 5.42, "state",
     [("Sao Paulo", "SP", "01310"), ("Rio de Janeiro", "RJ", "20040"),
      ("Belo Horizonte", "MG", "30110")],
     ["Correios", "Jadlog", "Loggi"]),
    ("India", 4, "INR", 83.5, "state",
     [("Bengaluru", "KA", "560001"), ("Mumbai", "MH", "400001"),
      ("Delhi", "DL", "110001"), ("Hyderabad", "TG", "500001")],
     ["Delhivery", "Blue Dart", "India Post"]),
    ("Sweden", 3, "SEK", 10.6, "county",
     [("Stockholm", "Stockholm", "111 20"), ("Gothenburg", "Vastra Gotaland", "411 03")],
     ["PostNord", "DHL", "Budbee"]),
    ("Singapore", 3, "SGD", 1.34, "district",
     [("Singapore", "Central", "018956")],
     ["SingPost", "Ninja Van", "DHL"]),
    ("Mexico", 3, "MXN", 17.1, "state",
     [("Mexico City", "CDMX", "06000"), ("Guadalajara", "JAL", "44100"),
      ("Monterrey", "NL", "64000")],
     ["Estafeta", "DHL", "FedEx"]),
]
NO_MINOR_UNITS = {"JPY", "KRW"}

# ---------------------------------------------------------------------------
# Catalog: category -> (subcategory, product name, brand, base USD price)
# Brands are invented; no real trademarks.
# ---------------------------------------------------------------------------
CATALOG = {
    "Electronics": [
        ("Accessories", "Laptop Stand", "Kestrel", 49.99),
        ("Wearables", "Smartwatch", "Nordvane", 199.00),
        ("Audio", "Wireless Earbuds", "Aurelis", 129.99),
        ("Audio", "Bluetooth Speaker", "Aurelis", 79.99),
        ("Peripherals", "Mechanical Keyboard", "Kestrel", 109.00),
        ("Displays", "4K Monitor", "Lumenwave", 379.00),
        ("Accessories", "USB-C Hub", "Kestrel", 44.50),
        ("Peripherals", "1080p Webcam", "Lumenwave", 69.00),
        ("Power", "20000mAh Power Bank", "Voltbridge", 39.99),
        ("Networking", "Mesh Wi-Fi Router", "Northvale", 159.00),
    ],
    "Health and Fitness": [
        ("Yoga", "Yoga Mat", "Cairnstone", 29.99),
        ("Strength", "Resistance Band Set", "Cairnstone", 24.99),
        ("Recovery", "Foam Roller", "Cairnstone", 32.00),
        ("Strength", "Adjustable Dumbbell Set", "Ironvale", 249.00),
        ("Cardio", "Speed Jump Rope", "Ironvale", 18.50),
        ("Recovery", "Percussion Massage Gun", "Pulsewell", 139.00),
        ("Tracking", "Heart Rate Monitor", "Pulsewell", 59.00),
    ],
    "Home and Kitchen": [
        ("Coffee", "Espresso Machine", "Marchetti", 449.00),
        ("Coffee", "Burr Coffee Grinder", "Marchetti", 129.00),
        ("Cookware", "Cast Iron Skillet", "Hearthford", 39.99),
        ("Appliances", "Air Fryer", "Hearthford", 119.00),
        ("Cutlery", "8-Piece Knife Set", "Hearthford", 89.00),
        ("Appliances", "High-Speed Blender", "Marchetti", 179.00),
        ("Storage", "Vacuum Seal Container Set", "Hearthford", 34.99),
    ],
    "Apparel": [
        ("Footwear", "Trail Running Shoes", "Fellrun", 129.00),
        ("Outerwear", "Waterproof Rain Jacket", "Fellrun", 159.00),
        ("Socks", "Merino Wool Socks", "Fellrun", 22.00),
        ("Tops", "Fleece Hoodie", "Cedarloft", 68.00),
        ("Bottoms", "Technical Joggers", "Cedarloft", 74.00),
    ],
    "Outdoors": [
        ("Camping", "2-Person Camping Tent", "Ridgeline", 219.00),
        ("Packs", "45L Hiking Backpack", "Ridgeline", 149.00),
        ("Hiking", "Carbon Trekking Poles", "Ridgeline", 89.00),
        ("Lighting", "Rechargeable Headlamp", "Northvale", 42.00),
        ("Hydration", "Insulated Water Bottle", "Northvale", 34.00),
    ],
    "Office": [
        ("Furniture", "Standing Desk", "Meridian Works", 549.00),
        ("Seating", "Ergonomic Task Chair", "Meridian Works", 389.00),
        ("Lighting", "LED Desk Lamp", "Lumenwave", 59.00),
        ("Accessories", "Dual Monitor Arm", "Meridian Works", 129.00),
        ("Storage", "Filing Cabinet", "Meridian Works", 199.00),
    ],
    "Beauty": [
        ("Skincare", "Vitamin C Serum", "Belleaire", 38.00),
        ("Skincare", "Ceramide Moisturizer", "Belleaire", 29.00),
        ("Haircare", "Ionic Hair Dryer", "Belleaire", 149.00),
        ("Tools", "Facial Cleansing Brush", "Belleaire", 54.00),
    ],
    "Pet Supplies": [
        ("Feeding", "Elevated Dog Bowl", "Waggonly", 34.00),
        ("Bedding", "Orthopedic Pet Bed", "Waggonly", 89.00),
        ("Toys", "Puzzle Treat Dispenser", "Waggonly", 19.99),
        ("Grooming", "Deshedding Brush", "Waggonly", 24.50),
    ],
    "Toys and Games": [
        ("Board Games", "Strategy Board Game", "Foxglove", 44.00),
        ("Puzzles", "1000-Piece Puzzle", "Foxglove", 21.00),
        ("Building", "Engineering Brick Set", "Foxglove", 79.00),
    ],
}
CATEGORY_WEIGHTS = {
    "Electronics": 26, "Home and Kitchen": 16, "Apparel": 14,
    "Health and Fitness": 12, "Office": 10, "Outdoors": 8,
    "Beauty": 6, "Pet Supplies": 5, "Toys and Games": 3,
}

# Plausible shipping weight ranges (kg) per category.
CATEGORY_WEIGHT_KG = {
    "Electronics": (0.05, 8.0), "Health and Fitness": (0.2, 26.0),
    "Home and Kitchen": (0.4, 16.0), "Apparel": (0.1, 1.8),
    "Outdoors": (0.15, 6.0), "Office": (0.3, 32.0),
    "Beauty": (0.05, 1.2), "Pet Supplies": (0.2, 7.0),
    "Toys and Games": (0.3, 3.5),
}

COLORS = ["black", "graphite", "white", "sand", "navy", "forest", "slate", "clay"]
SIZES = ["XS", "S", "M", "L", "XL", "one-size"]

FIRST = ["Avery", "Rowan", "Priya", "Mateo", "Ingrid", "Kenji", "Salma", "Hugo",
         "Nadia", "Emeka", "Lena", "Diego", "Mei", "Idris", "Freya", "Tomas",
         "Zara", "Omar", "Marta", "Ravi", "Sofia", "Anya", "Lucas", "Chiara",
         "Noor", "Felix", "Yuki", "Andre", "Elif", "Jonas", "Camila", "Wei"]
LAST = ["Weaver", "Delgado", "Okafor", "Nakamura", "Rossi", "Petrov", "Duarte",
        "Haddad", "Lindqvist", "Ferreira", "Novak", "Ibrahim", "Kaminski",
        "Bianchi", "Vance", "Almeida", "Rahman", "Sokolov", "Guzman", "Bright",
        "Yildiz", "Marsh", "Ortega", "Bergstrom", "Nakagawa", "Moreau"]

TIERS = [("bronze", 46), ("silver", 30), ("gold", 17), ("platinum", 7)]
CHANNELS = [("web", 52), ("mobile_app", 33), ("marketplace", 10), ("phone", 5)]
PAY_METHODS = [("credit_card", 58), ("debit_card", 16), ("paypal", 12),
               ("apple_pay", 8), ("bank_transfer", 4), ("gift_card", 2)]
CARD_BRANDS = ["visa", "mastercard", "amex", "discover"]
SHIP_METHODS = [("standard", 62, 5.99, (4, 9)), ("expedited", 26, 12.99, (2, 4)),
                ("overnight", 7, 24.99, (1, 2)), ("free", 5, 0.0, (5, 12))]
DISCOUNTS = [None, None, None, None, ("WELCOME10", 10), ("SPRING15", 15),
             ("BULK20", 20), ("LOYALTY5", 5), ("FLASH25", 25)]
RETURN_REASONS = ["wrong_size", "damaged_in_transit", "not_as_described",
                  "changed_mind", "arrived_late", "defective"]
# Fulfillment centres, with the real location each one ships from.
WAREHOUSES = [
    ("ATX-1", "Austin", "United States"), ("RNO-2", "Reno", "United States"),
    ("CMH-3", "Columbus", "United States"), ("FRA-1", "Frankfurt", "Germany"),
    ("SIN-1", "Singapore", "Singapore"), ("SYD-1", "Sydney", "Australia"),
    ("BOM-1", "Mumbai", "India"), ("YYZ-1", "Toronto", "Canada"),
    ("LHR-1", "London", "United Kingdom"),
]
# Prefer a warehouse in the destination country when one exists.
WAREHOUSES_BY_COUNTRY = {}
for _w in WAREHOUSES:
    WAREHOUSES_BY_COUNTRY.setdefault(_w[2], []).append(_w)


def wpick(pairs):
    labels = [p[0] for p in pairs]
    weights = [p[1] for p in pairs]
    return random.choices(labels, weights=weights, k=1)[0]


def money(value, currency):
    return int(round(value)) if currency in NO_MINOR_UNITS else round(value, 2)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def seasonal_weight(dt):
    """Q4 lift, plus a modest mid-summer dip."""
    m = dt.month
    if m in (11, 12):
        return 1.9
    if m == 10:
        return 1.25
    if m in (6, 7):
        return 0.85
    return 1.0


def build_order(seq, now, start, end, cust_pool):
    # ---- when ------------------------------------------------------------
    for _ in range(6):
        placed = datetime.fromtimestamp(
            random.uniform(start.timestamp(), end.timestamp()), tz=timezone.utc)
        if random.random() < seasonal_weight(placed) / 1.9:
            break
    age_days = (now - placed).days

    # ---- where -----------------------------------------------------------
    market = random.choices(MARKETS, weights=[m[1] for m in MARKETS], k=1)[0]
    country, _, currency, fx, region_label, cities, carriers = market
    city, region, postal = random.choice(cities)

    # ---- who -------------------------------------------------------------
    cust_n = random.randrange(1, cust_pool + 1)
    first, last = random.choice(FIRST), random.choice(LAST)
    tier = wpick(TIERS)

    # ---- what ------------------------------------------------------------
    category = wpick(list(CATEGORY_WEIGHTS.items()))
    subcategory, pname, brand, base_usd = random.choice(CATALOG[category])
    quantity = random.choices([1, 1, 1, 2, 2, 3, 4], k=1)[0]
    if placed.month in (11, 12) and random.random() < 0.25:
        quantity += 1

    unit_price = money(base_usd * fx, currency)
    subtotal = money(unit_price * quantity, currency)

    disc = random.choice(DISCOUNTS)
    if tier in ("gold", "platinum") and disc is None and random.random() < 0.3:
        disc = ("LOYALTY5", 5)
    disc_code, disc_pct = (disc if disc else (None, 0))
    disc_amount = money(subtotal * disc_pct / 100.0, currency)

    ship_method = wpick([(s[0], s[1]) for s in SHIP_METHODS])
    ship_spec = next(s for s in SHIP_METHODS if s[0] == ship_method)
    ship_cost = money(ship_spec[2] * fx, currency)
    if subtotal - disc_amount > money(150 * fx, currency) and random.random() < 0.55:
        ship_cost = money(0.0, currency)

    tax_rate = round(random.uniform(0.0, 0.21), 4)
    tax_amount = money((subtotal - disc_amount) * tax_rate, currency)
    total = money(subtotal - disc_amount + tax_amount + ship_cost, currency)

    # ---- lifecycle -------------------------------------------------------
    if age_days < 1:
        status = random.choices(["pending", "processing"], weights=[0.4, 0.6])[0]
    elif age_days < 3:
        status = random.choices(["processing", "shipped", "cancelled"],
                                weights=[0.35, 0.6, 0.05])[0]
    elif age_days < 10:
        status = random.choices(["shipped", "delivered", "cancelled"],
                                weights=[0.4, 0.56, 0.04])[0]
    else:
        status = random.choices(["delivered", "returned", "cancelled"],
                                weights=[0.9, 0.07, 0.03])[0]

    paid_at = placed + timedelta(seconds=random.randrange(2, 400))
    est_days = random.randrange(*ship_spec[3])
    shipped_at = (placed + timedelta(days=random.uniform(0.2, 2.0))
                  if status in ("shipped", "delivered", "returned") else None)
    delivered_at = (shipped_at + timedelta(days=random.uniform(est_days * 0.6,
                                                              est_days * 1.4))
                    if shipped_at and status in ("delivered", "returned") else None)

    # ship from a domestic warehouse when there is one, else cross-border
    if country in WAREHOUSES_BY_COUNTRY and random.random() < 0.85:
        wh_code, wh_city, wh_country = random.choice(WAREHOUSES_BY_COUNTRY[country])
    else:
        wh_code, wh_city, wh_country = random.choice(WAREHOUSES)

    shipping_events = []
    if shipped_at:
        shipping_events.append({"status": "label_created", "at": iso(shipped_at),
                                "location": {"city": wh_city,
                                             "country": wh_country}})
        shipping_events.append({"status": "in_transit",
                                "at": iso(shipped_at + timedelta(hours=random.randrange(4, 40))),
                                "location": {"city": city, "country": country}})
    if delivered_at:
        shipping_events.append({"status": "delivered", "at": iso(delivered_at),
                                "location": {"city": city, "country": country}})

    # ---- document --------------------------------------------------------
    carrier = random.choice(carriers)
    doc = {
        "order_id": f"ORDER-{seq:08d}",
        "order_date": iso(placed),
        "status": status,
        "channel": wpick(CHANNELS),
        "currency": currency,
        "fx_rate_to_usd": round(1.0 / fx, 6),
        "quantity": quantity,
        "unit_price": unit_price,
        "subtotal": subtotal,
        "discount": {"code": disc_code, "percent": disc_pct, "amount": disc_amount},
        "tax": {"rate": tax_rate, "amount": tax_amount},
        "total_amount": total,
        "amount_usd": round(total / fx, 2),
        "customer": {
            "id": f"CUST-{cust_n}",
            "name": {"first": first, "last": last},
            "email": f"{first.lower()}.{last.lower()}{random.randrange(1, 99)}@mail.test",
            "country": country,
            "city": city,
            "tier": tier,
            "segment": random.choice(["consumer", "consumer", "consumer", "business"]),
            "since": (placed - timedelta(days=random.randrange(30, 3600))).strftime("%Y-%m-%d"),
            "address": {
                "line1": f"{random.randrange(1, 999)} {random.choice(['Alder', 'Cedar', 'Harbor', 'Mill', 'Union', 'Quarry'])} "
                         f"{random.choice(['St', 'Ave', 'Rd', 'Ln'])}",
                "city": city,
                region_label: region,
                "postal_code": postal,
                "country": country,
            },
            "marketing_opt_in": random.random() < 0.42,
        },
        "product": {
            "sku": f"SKU-{category[:2].upper()}{abs(hash(pname)) % 100000:05d}",
            "name": pname,
            "category": category,
            "subcategory": subcategory,
            "brand": brand,
            "list_price_usd": base_usd,
            "attributes": {
                "color": random.choice(COLORS),
                "size": random.choice(SIZES) if category == "Apparel" else None,
                "weight_kg": round(random.uniform(*CATEGORY_WEIGHT_KG[category]), 2),
                "warranty_months": random.choice([0, 12, 12, 24, 36]),
            },
            "ratings": {"average": round(random.uniform(3.2, 4.9), 1),
                        "count": random.randrange(4, 9000)},
            "tags": random.sample(
                ["bestseller", "new", "clearance", "eco", "bundle", "limited"],
                k=random.randrange(0, 3)),
        },
        "shipping": {
            "method": ship_method,
            "carrier": carrier,
            "cost": ship_cost,
            "estimated_days": est_days,
            "tracking_number": (f"{carrier[:2].upper()}"
                                f"{random.randrange(10**10, 10**11)}"
                                if shipped_at else None),
            "shipped_at": iso(shipped_at) if shipped_at else None,
            "delivered_at": iso(delivered_at) if delivered_at else None,
            "destination": {"city": city, region_label: region,
                            "postal_code": postal, "country": country},
            "events": shipping_events,
        },
        "payment": {
            "method": wpick(PAY_METHODS),
            "status": "refunded" if status == "returned" else (
                "voided" if status == "cancelled" else "captured"),
            "authorized_at": iso(paid_at),
            "card": None,
            "installments": random.choices([1, 1, 1, 3, 6, 12], k=1)[0],
        },
        "fulfillment": {
            "warehouse": {"code": wh_code, "city": wh_city, "country": wh_country},
            "cross_border": wh_country != country,
            "picked_at": iso(placed + timedelta(hours=random.randrange(1, 30))),
            "packages": random.choices([1, 1, 1, 2], k=1)[0],
            "gift_wrap": random.random() < 0.08,
        },
        "return": None,
    }

    if doc["payment"]["method"] in ("credit_card", "debit_card"):
        doc["payment"]["card"] = {
            "brand": random.choice(CARD_BRANDS),
            "last4": f"{random.randrange(1000, 9999)}",
            "expiry": {"month": random.randrange(1, 13),
                       "year": random.randrange(2026, 2032)},
        }

    if status == "returned" and delivered_at:
        requested = delivered_at + timedelta(days=random.uniform(1, 25))
        doc["return"] = {
            "requested_at": iso(requested),
            "reason": random.choice(RETURN_REASONS),
            "condition": random.choice(["unopened", "opened", "damaged"]),
            "refund": {"amount": total, "currency": currency,
                       "processed_at": iso(requested + timedelta(days=random.uniform(1, 9))),
                       "restocking_fee": money(
                           total * random.choice([0.0, 0.0, 0.0, 0.1]), currency)},
            "rma": f"RMA-{random.randrange(10**6, 10**7)}",
        }

    return doc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=500_000)
    ap.add_argument("--days", type=float, default=730.0)
    ap.add_argument("--customers", type=int, default=120_000)
    ap.add_argument("--out", default="orders.parquet")
    ap.add_argument("--ndjson", default=None,
                    help="also write newline-delimited JSON to this path")
    ap.add_argument("--pretty-rate", type=float, default=0.0,
                    help="fraction of documents pretty-printed (default compact)")
    ap.add_argument("--sample", type=int, default=0,
                    help="print N documents and exit without writing files")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    random.seed(args.seed)
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=args.days)

    if args.sample:
        for i in range(args.sample):
            print(json.dumps(build_order(i + 1, now, start, now, args.customers),
                             indent=2))
            print()
        return

    messages = []
    for i in range(args.rows):
        doc = build_order(i + 1, now, start, now, args.customers)
        if args.pretty_rate and random.random() < args.pretty_rate:
            messages.append(json.dumps(doc, indent=2))
        else:
            messages.append(json.dumps(doc, separators=(",", ":")))

    table = pa.table({"message": pa.array(messages, type=pa.string())})
    pq.write_table(table, args.out, compression="snappy", row_group_size=50_000)

    if args.ndjson:
        with open(args.ndjson, "w", encoding="utf-8") as fh:
            for m in messages:
                fh.write(m.replace("\n", " ") + "\n")

    size = os.path.getsize(args.out) / 1e6
    raw = sum(len(m) for m in messages) / 1e6
    print(f"wrote {args.out}: {table.num_rows:,} rows x 1 col "
          f"({size:.1f} MB on disk, {raw:.1f} MB raw JSON)")
    print(f"  window    : {start:%Y-%m-%d} .. {now:%Y-%m-%d}")
    print(f"  customers : {args.customers:,} distinct")
    print(f"  markets   : {len(MARKETS)} countries, "
          f"{len({m[2] for m in MARKETS})} currencies")
    print(f"  catalog   : {sum(len(v) for v in CATALOG.values())} products "
          f"across {len(CATALOG)} categories")
    if args.ndjson:
        print(f"  ndjson    : {args.ndjson} "
              f"({os.path.getsize(args.ndjson) / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
