#!/usr/bin/env python3
"""
gen_parquet.py — 7-year historical transaction archive for the Fraud Workshop.

Complements the live Elasticsearch generators in this directory:

    wire-fraud.py         -> fraud-workshop-wire-fraud
    money-laundering.py   -> fraud-workshop-money-laundering
    smurfing.py           -> fraud-workshop-smurfing
    brokerage_workshop.py -> brokerage-workshop

Those four write the recent incident window (NOW-8d .. NOW). This script writes
everything BEFORE it (NOW-7y .. NOW-9d) to Parquet for ES|QL Data Federation,
using the same event schema, the same accountID space (1..35000), the same
enrichment ID ranges, and the same Austin business-hours distribution.

The 22 known fraud-persona accounts behave NORMALLY in this archive. That is
deliberate: the teaching point is that their recent activity is anomalous
relative to a seven-year baseline, not that they carry a flag.

Usage:
    python3 gen_parquet.py                         # 1M rows, hive-partitioned
    python3 gen_parquet.py --rows 5000000
    python3 gen_parquet.py --single --out archive.parquet
    python3 gen_parquet.py --years 3 --out-dir ./hist
"""
import argparse
import os
import random
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pyarrow as pa
import pyarrow.parquet as pq

AUSTIN_TZ = ZoneInfo("America/Chicago")

# ---------------------------------------------------------------------------
# Vocabularies — taken verbatim from the V2 generators so the archive and the
# live indices share one set of values.
# ---------------------------------------------------------------------------
BANK_ACCOUNT_TYPES = ["checking", "savings", "money market"]
BROK_ACCOUNT_TYPES = ["brokerage", "ira", "roth_ira", "margin"]

# money-laundering.py / wire-fraud.py event mix
BANK_EVENTS = ["purchase", "withdrawal", "wire", "fee", "deposit"]
BANK_WEIGHTS = [0.40, 0.25, 0.20, 0.10, 0.05]
# smurfing.py also emits these low-value non-monetary events
BANK_NOISE_EVENTS = ["inquiry", "status_check"]

BROK_EVENTS = ["buy", "sell", "dividend", "fee", "transfer", "liquidation"]
BROK_WEIGHTS = [0.42, 0.34, 0.10, 0.07, 0.05, 0.02]

# brokerage_workshop.py security universe
EQUITIES = [
    ("AAPL", "equity", 170, 230), ("MSFT", "equity", 380, 470),
    ("AMZN", "equity", 150, 210), ("NVDA", "equity", 95, 150),
    ("GOOGL", "equity", 150, 200), ("TSLA", "equity", 170, 360),
    ("JPM", "equity", 190, 270), ("BRK.B", "equity", 400, 480),
]
ETFS = [
    ("VOO", "etf", 480, 560), ("VTI", "etf", 250, 300),
    ("SPY", "etf", 520, 600), ("QQQ", "etf", 440, 530),
    ("BND", "etf", 70, 76),
]
THIN = [
    ("ZXCO", "equity", 2, 9), ("BLTX", "equity", 1, 6),
    ("QNTM", "equity", 3, 12), ("HLIO", "equity", 4, 15),
]
ALL_SECURITIES = EQUITIES + ETFS + THIN
# Historical baseline is boring: mostly blue chips and index funds. Thinly
# traded names stay rare here so the recent wash-trading volume stands out.
HIST_SECURITIES = EQUITIES + ETFS + ETFS + THIN[:1]

# Enrichment ID ranges — must match the generators for enrich policies to hit
MAX_ACCOUNT_ID = 35_000
POS_ID_MAX = 13_000       # enrich-austinstores
TXBANK_ID_MAX = 30        # enrich-austinbanks
INTBANK_ID_MAX = 25       # enrich-intbank
BROKER_ID_MAX = 40        # enrich-brokers
ADDRESS_ID_MAX = 35_000

# Known persona accounts (see the V2 FraudConfig classes). Listed so they can be
# held to a clean baseline, NOT so they can be flagged.
PERSONA_ACCOUNTS = set(
    list(range(2, 22, 2))                    # smurfing.py fraud_accounts
    + [32687, 16384, 8192, 4096, 2048]       # money-laundering.py chain
    + [1594, 21162, 1874]                    # brokerage layering
    + [2718, 3141, 1618, 1414]               # brokerage wash trading
)


def pick_security(pool):
    sym, stype, lo, hi = random.choice(pool)
    return sym, stype, round(random.uniform(lo, hi), 2)


def business_timestamp(start_epoch, end_epoch):
    """Austin-weighted timestamp: weekday-heavy, 9am-6pm peak, tail to 9pm."""
    for _ in range(12):
        ts = datetime.fromtimestamp(
            random.uniform(start_epoch, end_epoch), tz=timezone.utc)
        local = ts.astimezone(AUSTIN_TZ)
        # weekends are quiet but not empty
        if local.weekday() >= 5 and random.random() > 0.22:
            continue
        h = local.hour
        if 9 <= h < 18:
            return ts                       # peak banking hours
        if 7 <= h < 21 and random.random() < 0.35:
            return ts                       # shoulder
        if random.random() < 0.04:
            return ts                       # overnight card/ATM tail
    return ts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=1_000_000)
    ap.add_argument("--years", type=float, default=7.0)
    ap.add_argument("--gap-days", type=int, default=9,
                    help="archive ends this many days before now, leaving room "
                         "for the live generators' NOW-8d window")
    ap.add_argument("--out-dir", default="transactions_history",
                    help="hive-partitioned output directory (year=/month=)")
    ap.add_argument("--out", default="transactions.parquet",
                    help="output file when --single is used")
    ap.add_argument("--single", action="store_true",
                    help="write one flat .parquet instead of partitions")
    ap.add_argument("--brokerage-ratio", type=float, default=0.22)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    random.seed(args.seed)

    now = datetime.now(timezone.utc)
    end = now - timedelta(days=args.gap_days)
    start = end - timedelta(days=365.25 * args.years)
    start_epoch, end_epoch = start.timestamp(), end.timestamp()

    # A minority of accounts drive most volume, as in real retail banking.
    heavy = set(random.sample(range(1, MAX_ACCOUNT_ID + 1), 3_500))

    cols = {k: [] for k in [
        "accountID", "event_amount", "event_type", "account_type",
        "account_event", "transaction_date", "timestamp",
        "deposit_type", "wire_direction", "posID", "txbankId", "addressId",
        "intbankID", "to_account",
        "security_symbol", "security_type", "quantity", "price_per_unit",
        "settlement_date", "counterparty_account", "brokerID", "tradeID",
        "data_origin",
    ]}

    trade_seq = 0
    for i in range(args.rows):
        acct = (random.choice(tuple(heavy)) if random.random() < 0.55
                else random.randrange(1, MAX_ACCOUNT_ID + 1))
        ts = business_timestamp(start_epoch, end_epoch)
        iso = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"

        # defaults — every optional field null unless the event sets it
        (deposit_type, wire_direction, pos_id, txbank_id, intbank_id,
         to_account) = (None, None, None, None, None, None)
        (sym, stype, qty, px, settle, counterparty, broker_id, trade_id) = (
            None, None, None, None, None, None, None, None)

        if random.random() < args.brokerage_ratio:
            # ---------------- brokerage-workshop shaped event ----------------
            event = random.choices(BROK_EVENTS, weights=BROK_WEIGHTS)[0]
            acct_type = random.choice(BROK_ACCOUNT_TYPES)
            broker_id = random.randint(1, BROKER_ID_MAX)
            sym, stype, px = pick_security(HIST_SECURITIES)

            if event == "buy":
                etype = "debit"
                amount = round(random.lognormvariate(7.9, 0.85), 2)
            elif event in ("sell", "liquidation"):
                etype = "credit"
                amount = round(random.lognormvariate(7.9, 0.9), 2)
            elif event == "dividend":
                etype = "credit"
                amount = round(random.lognormvariate(4.6, 0.8), 2)
            elif event == "fee":
                etype = "debit"
                amount = round(random.uniform(0.95, 34.95), 2)
                sym = stype = px = None
            else:  # transfer
                etype = random.choice(["debit", "credit"])
                amount = round(random.lognormvariate(8.4, 0.95), 2)
                sym = stype = px = None
                wire_direction = random.choice(["inbound", "outbound"])
                intbank_id = random.randint(1, INTBANK_ID_MAX)

            if sym and event != "dividend":
                qty = round(amount / px, 4)
                trade_seq += 1
                trade_id = f"TRD-{ts.year}{trade_seq:08d}"
                settle_dt = ts + timedelta(days=random.choice([1, 2]))
                settle = settle_dt.strftime("%Y-%m-%d")
                counterparty = random.randrange(1, MAX_ACCOUNT_ID + 1)
        else:
            # ---------------- banking shaped event ---------------------------
            if random.random() < 0.07:
                event = random.choice(BANK_NOISE_EVENTS)
                etype = "debit"
                amount = 0.0
                acct_type = random.choice(BANK_ACCOUNT_TYPES)
            else:
                event = random.choices(BANK_EVENTS, weights=BANK_WEIGHTS)[0]
                acct_type = random.choice(BANK_ACCOUNT_TYPES)

                if event == "purchase":
                    etype = "debit"
                    amount = round(random.lognormvariate(3.5, 1.05), 2)
                    pos_id = random.randint(1, POS_ID_MAX)
                elif event == "withdrawal":
                    etype = "debit"
                    amount = float(random.choice([20, 40, 60, 80, 100, 200, 300, 500]))
                elif event == "wire":
                    etype = random.choices(["debit", "credit"], weights=[0.6, 0.4])[0]
                    amount = round(random.lognormvariate(8.1, 1.0), 2)
                    txbank_id = random.randint(1, TXBANK_ID_MAX)
                    if random.random() < 0.10:
                        wire_direction = random.choice(["inbound", "outbound"])
                        intbank_id = random.randint(1, INTBANK_ID_MAX)
                    if random.random() < 0.15:
                        to_account = random.randrange(1, MAX_ACCOUNT_ID + 1)
                elif event == "fee":
                    etype = "debit"
                    amount = round(random.choice([1.50, 2.50, 3.00, 12.00, 15.00,
                                                  25.00, 35.00]), 2)
                else:  # deposit
                    etype = "credit"
                    amount = round(random.lognormvariate(6.6, 1.15), 2)
                    deposit_type = random.choices(
                        ["payroll", "cash", "check", "transfer"],
                        weights=[0.46, 0.18, 0.24, 0.12])[0]

        # Persona accounts keep an unremarkable history. Cap their historical
        # amounts so the recent-window spike is genuinely anomalous.
        if acct in PERSONA_ACCOUNTS and amount > 2_500:
            amount = round(amount * random.uniform(0.06, 0.22), 2)
            if qty and px:
                qty = round(amount / px, 4)

        cols["accountID"].append(acct)
        cols["event_amount"].append(amount)
        cols["event_type"].append(etype)
        cols["account_type"].append(acct_type)
        cols["account_event"].append(event)
        cols["transaction_date"].append(iso)
        cols["timestamp"].append(ts)
        cols["deposit_type"].append(deposit_type)
        cols["wire_direction"].append(wire_direction)
        cols["posID"].append(pos_id)
        cols["txbankId"].append(txbank_id)
        cols["addressId"].append(
            acct if acct <= ADDRESS_ID_MAX else None)
        cols["intbankID"].append(intbank_id)
        cols["to_account"].append(to_account)
        cols["security_symbol"].append(sym)
        cols["security_type"].append(stype)
        cols["quantity"].append(qty)
        cols["price_per_unit"].append(px)
        cols["settlement_date"].append(settle)
        cols["counterparty_account"].append(counterparty)
        cols["brokerID"].append(broker_id)
        cols["tradeID"].append(trade_id)
        cols["data_origin"].append("historical_archive")

    schema = pa.schema([
        ("accountID", pa.int32()),
        ("event_amount", pa.float64()),
        ("event_type", pa.string()),
        ("account_type", pa.string()),
        ("account_event", pa.string()),
        ("transaction_date", pa.string()),
        ("timestamp", pa.timestamp("ms", tz="UTC")),
        ("deposit_type", pa.string()),
        ("wire_direction", pa.string()),
        ("posID", pa.int32()),
        ("txbankId", pa.int32()),
        ("addressId", pa.int32()),
        ("intbankID", pa.int32()),
        ("to_account", pa.int32()),
        ("security_symbol", pa.string()),
        ("security_type", pa.string()),
        ("quantity", pa.float64()),
        ("price_per_unit", pa.float64()),
        ("settlement_date", pa.string()),
        ("counterparty_account", pa.int32()),
        ("brokerID", pa.int32()),
        ("tradeID", pa.string()),
        ("data_origin", pa.string()),
    ])

    table = pa.Table.from_pydict(cols, schema=schema)

    if args.single:
        pq.write_table(table, args.out, compression="snappy",
                       row_group_size=100_000)
        target = args.out
    else:
        years = pa.compute.year(table["timestamp"])
        months = pa.compute.month(table["timestamp"])
        table = table.append_column("year", years.cast(pa.int32())) \
                     .append_column("month", months.cast(pa.int32()))
        pq.write_to_dataset(
            table,
            root_path=args.out_dir,
            partition_cols=["year", "month"],
            compression="snappy",
            existing_data_behavior="delete_matching",
        )
        target = args.out_dir + "/  (year=YYYY/month=M)"

    size = 0
    for root, _, files in os.walk(args.out_dir if not args.single else "."):
        for f in files:
            if f.endswith(".parquet") and (args.single is False or f == args.out):
                size += os.path.getsize(os.path.join(root, f))

    print(f"wrote {target}")
    print(f"  {table.num_rows:,} rows x {len(schema)} cols, {size / 1e6:.1f} MB")
    print(f"  window: {start:%Y-%m-%d} .. {end:%Y-%m-%d} "
          f"(ends {args.gap_days}d before now)")


if __name__ == "__main__":
    main()
