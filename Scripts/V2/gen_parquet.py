#!/usr/bin/env python3
"""
gen_parquet.py — 7-year historical transaction archive for the Fraud Workshop.

Complements the live Elasticsearch generators in this directory:

    wire-fraud.py           -> fraud-workshop-wire-fraud
    money-laundering.py     -> fraud-workshop-money-laundering
    smurfing.py             -> fraud-workshop-smurfing
    brokerage_workshop.py   -> brokerage-workshop

Those four write the recent incident window (NOW-8d .. NOW). This script writes
everything BEFORE it (NOW-7y .. NOW-9d) to Parquet for ES|QL Data Federation.

ACCOUNT SPACE — 50,000,000 accounts (identity.py is authoritative):

    1 .. 50,000,000           full account space
    49,000,001 .. 49,020,025  the 20,025 company employees (identity.py),
                              one account per employee. Employee rows carry
                              company_employee = true and the 7-digit
                              employee_id ("0000356").
    everything else           individuals, corporations (by sector),
                              government entities (county / state / federal),
                              and unions (teacher, police, fire_fighter,
                              steel_worker, railroad, emt, nurses_doctors,
                              manufacturing_* by industry group). Holder type
                              is a deterministic function of the account id,
                              so live generators and enrich lookups can
                              recompute it without reading this file.

Every employee is guaranteed at least --employee-min-events rows so the
employee <-> transaction join is total, not probabilistic.

SUSPICIOUS PATTERNS woven into the archive (in addition to the recent-window
personas, which keep their clean historical baseline):

  * SECURITIES FRAUD — employee 0011209 (Finance > Stock_Administration,
    account 49,011,209) repeatedly buys thinly-traded symbols and sells one
    to three days later into a 25-90% price jump, roughly nine times a year,
    every year. No flag column marks it; the tell is the win rate and the
    timing against the thin symbols' baseline volume.

  * GOVERNMENT STRUCTURING — county account 23,114,007 makes cash
    withdrawals of $9,000-$9,900 two to four times a week, concentrated on
    late Fridays and off-hours, escalating over the final three years.
    Individually unremarkable; the pattern is the point.

The 22 known fraud-persona accounts from the live generators still behave
NORMALLY here: their recent activity must be anomalous against a clean
seven-year baseline.

Usage:
    python3 gen_parquet.py                          # 1M rows, hive-partitioned
    python3 gen_parquet.py --rows 5000000
    python3 gen_parquet.py --single --out archive.parquet
    python3 gen_parquet.py --years 3 --out-dir ./hist
"""

import argparse
import importlib.util
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pyarrow as pa
import pyarrow.parquet as pq


def _load_identity():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "identity.py")
    if not os.path.exists(path):
        sys.exit("identity.py must sit next to this script")
    spec = importlib.util.spec_from_file_location("identity", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.IDENTITY_VERSION == "1", "identity.py version mismatch"
    return mod


I = _load_identity()

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
# traded names stay rare here so both the recent wash-trading volume AND the
# insider's thin-symbol concentration stand out.
HIST_SECURITIES = EQUITIES + ETFS + ETFS + THIN[:1]

# Enrichment ID ranges — must match the generators for enrich policies to hit.
# The account space itself now comes from identity.py (50M); the legacy
# 1..35000 retail band keeps its addressId join.
MAX_ACCOUNT_ID = I.TOTAL_ACCOUNTS
LEGACY_ACCOUNT_ID_MAX = 35_000    # live-generator / enrich account band
POS_ID_MAX = 13_000               # enrich-austinstores
TXBANK_ID_MAX = 30                # enrich-austinbanks
INTBANK_ID_MAX = 25               # enrich-intbank
BROKER_ID_MAX = 40                # enrich-brokers
ADDRESS_ID_MAX = 35_000

# Known persona accounts (see the V2 FraudConfig classes). Listed so they can
# be held to a clean baseline, NOT so they can be flagged.
PERSONA_ACCOUNTS = set(
    list(range(2, 22, 2))                       # smurfing.py fraud_accounts
    + [32687, 16384, 8192, 4096, 2048]          # money-laundering.py chain
    + [1594, 21162, 1874]                       # brokerage layering
    + [2718, 3141, 1618, 1414]                  # brokerage wash trading
)

COLUMNS = [
    "accountID", "event_amount", "event_type", "account_type",
    "account_event", "transaction_date", "timestamp",
    "deposit_type", "wire_direction", "posID", "txbankId", "addressId",
    "intbankID", "to_account",
    "security_symbol", "security_type", "quantity", "price_per_unit",
    "settlement_date", "counterparty_account", "brokerID", "tradeID",
    "account_holder_type", "account_holder_subtype",
    "company_employee", "employee_id",
    "data_origin",
]


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
            return ts            # peak banking hours
        if 7 <= h < 21 and random.random() < 0.35:
            return ts            # shoulder
        if random.random() < 0.04:
            return ts            # overnight card/ATM tail
    return ts


def iso_ms(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------------------
# Row assembly
# ---------------------------------------------------------------------------

_trade_seq = 0


def _next_trade_id(ts):
    global _trade_seq
    _trade_seq += 1
    return f"TRD-{ts.year}{_trade_seq:08d}"


def base_row(acct, ts):
    holder_type, holder_sub, emp_id = I.account_holder(acct)
    return {
        "accountID": acct,
        "event_amount": 0.0,
        "event_type": "debit",
        "account_type": None,
        "account_event": None,
        "transaction_date": iso_ms(ts),
        "timestamp": ts,
        "deposit_type": None, "wire_direction": None, "posID": None,
        "txbankId": None,
        "addressId": acct if acct <= ADDRESS_ID_MAX else None,
        "intbankID": None, "to_account": None,
        "security_symbol": None, "security_type": None, "quantity": None,
        "price_per_unit": None, "settlement_date": None,
        "counterparty_account": None, "brokerID": None, "tradeID": None,
        "account_holder_type": holder_type,
        "account_holder_subtype": holder_sub,
        "company_employee": emp_id is not None,
        "employee_id": emp_id,
        "data_origin": "historical_archive",
    }


def brokerage_event(acct, ts):
    row = base_row(acct, ts)
    event = random.choices(BROK_EVENTS, weights=BROK_WEIGHTS)[0]
    row["account_event"] = event
    row["account_type"] = random.choice(BROK_ACCOUNT_TYPES)
    row["brokerID"] = random.randint(1, BROKER_ID_MAX)
    sym, stype, px = pick_security(HIST_SECURITIES)

    if event == "buy":
        row["event_type"] = "debit"
        amount = round(random.lognormvariate(7.9, 0.85), 2)
    elif event in ("sell", "liquidation"):
        row["event_type"] = "credit"
        amount = round(random.lognormvariate(7.9, 0.9), 2)
    elif event == "dividend":
        row["event_type"] = "credit"
        amount = round(random.lognormvariate(4.6, 0.8), 2)
    elif event == "fee":
        row["event_type"] = "debit"
        amount = round(random.uniform(0.95, 34.95), 2)
        sym = stype = px = None
    else:  # transfer
        row["event_type"] = random.choice(["debit", "credit"])
        amount = round(random.lognormvariate(8.4, 0.95), 2)
        sym = stype = px = None
        row["wire_direction"] = random.choice(["inbound", "outbound"])
        row["intbankID"] = random.randint(1, INTBANK_ID_MAX)

    row["event_amount"] = amount
    if sym and event != "dividend":
        row["security_symbol"], row["security_type"] = sym, stype
        row["price_per_unit"] = px
        row["quantity"] = round(amount / px, 4)
        row["tradeID"] = _next_trade_id(ts)
        settle_dt = ts + timedelta(days=random.choice([1, 2]))
        row["settlement_date"] = settle_dt.strftime("%Y-%m-%d")
        row["counterparty_account"] = random.randrange(1, MAX_ACCOUNT_ID + 1)
    elif sym:
        row["security_symbol"], row["security_type"] = sym, stype
        row["price_per_unit"] = px
    return row


def banking_event(acct, ts, holder_type="individual"):
    row = base_row(acct, ts)
    if random.random() < 0.07:
        row["account_event"] = random.choice(BANK_NOISE_EVENTS)
        row["event_type"] = "debit"
        row["event_amount"] = 0.0
        row["account_type"] = random.choice(BANK_ACCOUNT_TYPES)
        return row

    event = random.choices(BANK_EVENTS, weights=BANK_WEIGHTS)[0]
    row["account_event"] = event
    row["account_type"] = random.choice(BANK_ACCOUNT_TYPES)

    # Institutional accounts move institutional money.
    scale = {"individual": 0.0, "corporation": 1.6,
             "government": 1.9, "union": 1.2}[holder_type]

    if event == "purchase":
        row["event_type"] = "debit"
        row["event_amount"] = round(random.lognormvariate(3.5 + scale, 1.05), 2)
        row["posID"] = random.randint(1, POS_ID_MAX)
    elif event == "withdrawal":
        row["event_type"] = "debit"
        row["event_amount"] = float(random.choice(
            [20, 40, 60, 80, 100, 200, 300, 500]))
        if holder_type != "individual":
            row["event_amount"] *= random.choice([5, 10, 20])
    elif event == "wire":
        row["event_type"] = random.choices(["debit", "credit"],
                                           weights=[0.6, 0.4])[0]
        row["event_amount"] = round(random.lognormvariate(8.1 + scale, 1.0), 2)
        row["txbankId"] = random.randint(1, TXBANK_ID_MAX)
        if random.random() < 0.10:
            row["wire_direction"] = random.choice(["inbound", "outbound"])
            row["intbankID"] = random.randint(1, INTBANK_ID_MAX)
        if random.random() < 0.15:
            row["to_account"] = random.randrange(1, MAX_ACCOUNT_ID + 1)
    elif event == "fee":
        row["event_type"] = "debit"
        row["event_amount"] = round(random.choice(
            [1.50, 2.50, 3.00, 12.00, 15.00, 25.00, 35.00]), 2)
    else:  # deposit
        row["event_type"] = "credit"
        row["event_amount"] = round(random.lognormvariate(6.6 + scale, 1.15), 2)
        row["deposit_type"] = random.choices(
            ["payroll", "cash", "check", "transfer"],
            weights=[0.46, 0.18, 0.24, 0.12])[0]
    return row


def random_event(acct, start_epoch, end_epoch, brokerage_ratio):
    ts = business_timestamp(start_epoch, end_epoch)
    holder_type, _, _ = I.account_holder(acct)
    if holder_type == "individual" and random.random() < brokerage_ratio:
        row = brokerage_event(acct, ts)
    else:
        row = banking_event(acct, ts, holder_type)

    # Persona accounts keep an unremarkable history. Cap their historical
    # amounts so the recent-window spike is genuinely anomalous.
    if acct in PERSONA_ACCOUNTS and row["event_amount"] > 2_500:
        row["event_amount"] = round(
            row["event_amount"] * random.uniform(0.06, 0.22), 2)
        if row["quantity"] and row["price_per_unit"]:
            row["quantity"] = round(
                row["event_amount"] / row["price_per_unit"], 4)
    return row


# ---------------------------------------------------------------------------
# Fraud narratives
# ---------------------------------------------------------------------------

def securities_fraud_rows(start, end):
    """Employee 0011209 (Finance > Stock_Administration): recurring
    buy-thin / sell-into-spike cycles, ~9 per year across the window."""
    acct = I.SEC_FRAUD_ACCOUNT
    rows = []
    cycles = max(4, int((end - start).days / 365.25 * 9))
    for _ in range(cycles):
        sym, stype, lo, hi = random.choice(THIN)
        buy_ts = business_timestamp(start.timestamp(),
                                    (end - timedelta(days=5)).timestamp())
        buy_px = round(random.uniform(lo, lo + (hi - lo) * 0.35), 2)
        qty = round(random.uniform(4_000, 30_000), 4)

        buy = base_row(acct, buy_ts)
        buy.update({
            "account_event": "buy", "event_type": "debit",
            "account_type": "brokerage",
            "event_amount": round(qty * buy_px, 2),
            "security_symbol": sym, "security_type": stype,
            "quantity": qty, "price_per_unit": buy_px,
            "tradeID": _next_trade_id(buy_ts),
            "settlement_date": (buy_ts + timedelta(days=2)).strftime("%Y-%m-%d"),
            "counterparty_account": random.randrange(1, MAX_ACCOUNT_ID + 1),
            "brokerID": random.randint(1, BROKER_ID_MAX),
        })
        rows.append(buy)

        sell_ts = buy_ts + timedelta(days=random.uniform(1.0, 3.0))
        sell_px = round(buy_px * random.uniform(1.25, 1.90), 2)
        sell = base_row(acct, sell_ts)
        sell.update({
            "account_event": "sell", "event_type": "credit",
            "account_type": "brokerage",
            "event_amount": round(qty * sell_px, 2),
            "security_symbol": sym, "security_type": stype,
            "quantity": qty, "price_per_unit": sell_px,
            "tradeID": _next_trade_id(sell_ts),
            "settlement_date": (sell_ts + timedelta(days=2)).strftime("%Y-%m-%d"),
            "counterparty_account": random.randrange(1, MAX_ACCOUNT_ID + 1),
            "brokerID": random.randint(1, BROKER_ID_MAX),
        })
        rows.append(sell)
    return rows


def gov_structuring_rows(start, end):
    """County account 23,114,007: cash withdrawals of $9,000-$9,900, two to
    four times a week over the final three years, biased to late Friday and
    off-hours, escalating in frequency toward the present."""
    acct = I.GOV_SUSPECT_ACCOUNT
    rows = []
    window_start = max(start, end - timedelta(days=365 * 3))
    day = window_start
    while day < end:
        # escalation: 2/wk early, up to 4/wk near the end
        progress = (day - window_start).days / max(1, (end - window_start).days)
        per_week = 2 + progress * 2
        for _ in range(int(per_week) + (1 if random.random() < per_week % 1 else 0)):
            offset = random.uniform(0, 7)
            ts = (day + timedelta(days=offset)).astimezone(timezone.utc)
            local = ts.astimezone(AUSTIN_TZ)
            # push toward Friday 16:00-19:00 or the small hours
            if random.random() < 0.6:
                shift = (4 - local.weekday()) % 7
                local = local.replace(hour=random.randint(16, 18),
                                      minute=random.randint(0, 59))
                local += timedelta(days=shift)
            else:
                local = local.replace(hour=random.choice([5, 6, 21, 22]),
                                      minute=random.randint(0, 59))
            ts = local.astimezone(timezone.utc)
            if ts >= end:
                continue
            row = base_row(acct, ts)
            row.update({
                "account_event": "withdrawal", "event_type": "debit",
                "account_type": "checking",
                "event_amount": round(random.uniform(9_000, 9_900), 2),
            })
            rows.append(row)
        day += timedelta(days=7)
    return rows


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

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
    ap.add_argument("--employee-min-events", type=int, default=2,
                    help="guaranteed rows per employee account "
                         "(%d employees)" % I.NUM_EMPLOYEES)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    random.seed(args.seed)

    now = datetime.now(timezone.utc)
    end = now - timedelta(days=args.gap_days)
    start = end - timedelta(days=365.25 * args.years)
    start_epoch, end_epoch = start.timestamp(), end.timestamp()

    # A minority of accounts drive most volume, as in real retail banking.
    heavy = random.sample(range(1, MAX_ACCOUNT_ID + 1), 350_000)

    cols = {k: [] for k in COLUMNS}

    def append(row):
        for k in COLUMNS:
            cols[k].append(row[k])

    # ---- fraud narratives (carved out of --rows) ---------------------------
    fraud_rows = securities_fraud_rows(start, end) + gov_structuring_rows(start, end)
    for row in fraud_rows:
        append(row)

    # ---- guaranteed employee coverage --------------------------------------
    emp_rows = 0
    for emp in range(1, I.NUM_EMPLOYEES + 1):
        acct = I.employee_account(emp)
        for _ in range(args.employee_min_events):
            append(random_event(acct, start_epoch, end_epoch,
                                args.brokerage_ratio))
            emp_rows += 1

    # ---- the general population --------------------------------------------
    remaining = max(0, args.rows - len(fraud_rows) - emp_rows)
    if args.rows < len(fraud_rows) + emp_rows:
        print(f"warning: --rows {args.rows:,} is below the "
              f"{len(fraud_rows) + emp_rows:,} injected/guaranteed rows; "
              f"output will exceed --rows")
    for _ in range(remaining):
        if random.random() < 0.55:
            acct = random.choice(heavy)
        elif random.random() < 0.004:
            # employees also show up organically, not only via the guarantee
            acct = I.employee_account(random.randrange(1, I.NUM_EMPLOYEES + 1))
        else:
            acct = random.randrange(1, MAX_ACCOUNT_ID + 1)
        append(random_event(acct, start_epoch, end_epoch, args.brokerage_ratio))

    schema = pa.schema([
        ("accountID", pa.int64()),
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
        ("to_account", pa.int64()),
        ("security_symbol", pa.string()),
        ("security_type", pa.string()),
        ("quantity", pa.float64()),
        ("price_per_unit", pa.float64()),
        ("settlement_date", pa.string()),
        ("counterparty_account", pa.int64()),
        ("brokerID", pa.int32()),
        ("tradeID", pa.string()),
        ("account_holder_type", pa.string()),
        ("account_holder_subtype", pa.string()),
        ("company_employee", pa.bool_()),
        ("employee_id", pa.string()),
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
        target = args.out_dir + "/ (year=YYYY/month=M)"

    size = 0
    for root, _, files in os.walk(args.out_dir if not args.single else "."):
        for f in files:
            if f.endswith(".parquet") and (args.single is False or f == args.out):
                size += os.path.getsize(os.path.join(root, f))

    n_emp_total = sum(1 for v in cols["company_employee"] if v)
    print(f"wrote {target}")
    print(f"  {table.num_rows:,} rows x {len(schema)} cols, {size / 1e6:.1f} MB")
    print(f"  window    : {start:%Y-%m-%d} .. {end:%Y-%m-%d} "
          f"(ends {args.gap_days}d before now)")
    print(f"  accounts  : 1 .. {MAX_ACCOUNT_ID:,} "
          f"(employees at {I.EMPLOYEE_ACCOUNT_BASE + 1:,} .. "
          f"{I.EMPLOYEE_ACCOUNT_BASE + I.NUM_EMPLOYEES:,})")
    print(f"  employees : {n_emp_total:,} rows across all {I.NUM_EMPLOYEES:,} "
          f"employees (min {args.employee_min_events} each)")
    print(f"  narratives: {len(fraud_rows):,} rows "
          f"(securities fraud acct {I.SEC_FRAUD_ACCOUNT:,} / emp "
          f"{I.employee_id_str(I.SEC_FRAUD_EMP_ID)}, "
          f"county structuring acct {I.GOV_SUSPECT_ACCOUNT:,})")


if __name__ == "__main__":
    main()
