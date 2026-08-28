#!/usr/bin/env python3
"""
gen_hr_csv.py — HR roster for the 20,025 employees defined in identity.py.

One row per employee. Every value is a pure function of the employee id
(keyed hashing in identity.py), so the roster is byte-identical across runs
and machines, and any other generator can independently compute the same
person without reading this file.

Columns:
    Employee_ID     7 digits, always leading zero (356 -> 0000356)
    First_Name, Last_Name
    Department      Sales / Engineering / Marketing / Support / Finance /
                    Legal / Leadership
    Team            replaces the old Sub-Department column; includes the new
                    Finance > Stock_Administration team
    Start_Date      YYYY-MM-DD, uniform over 2012-03-15 .. 2026-03-15
    IP_Address      the employee's workstation address in 10.49.0.0/17 —
                    the join key for clientIp values parsed out of the
                    application logs

The suspicious log actor (10.49.110.17) and the securities-fraud employee
(0011209, Finance > Stock_Administration) are both present as perfectly
ordinary rows. The roster must not give the game away.

Usage:
    python3 gen_hr_csv.py
    python3 gen_hr_csv.py --out hr_roster.csv
    python3 gen_hr_csv.py --limit 500              # small sample for testing
    python3 gen_hr_csv.py --parquet hr_roster.parquet
"""

import argparse
import csv
import importlib.util
import os
import sys


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


def _load_garage_s3():
    """Optional Garage/S3 sink (garage_s3.py next to this script). Returns
    None when absent so local-only runs keep working without it."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "garage_s3.py")
    if not os.path.exists(path):
        return None
    spec = importlib.util.spec_from_file_location("garage_s3", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.GARAGE_S3_VERSION == "1", "garage_s3.py version mismatch"
    return mod

S3 = _load_garage_s3()

HEADER = ["Employee_ID", "First_Name", "Last_Name", "Department", "Team",
          "Start_Date", "IP_Address"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="hr_roster.csv")
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N rows (0 = all %d)" % I.NUM_EMPLOYEES)
    ap.add_argument("--parquet", default=None,
                    help="also write a Parquet copy to this path")
    if S3 is not None:
        S3.add_args(ap, default_prefix="hr")
    else:
        ap.add_argument("--s3", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    total = I.NUM_EMPLOYEES if not args.limit else min(args.limit, I.NUM_EMPLOYEES)

    rows = []
    dept_counts = {}
    team_counts = {}
    for emp in range(1, total + 1):
        p = I.employee(emp)
        dept_counts[p["department"]] = dept_counts.get(p["department"], 0) + 1
        key = (p["department"], p["team"])
        team_counts[key] = team_counts.get(key, 0) + 1
        rows.append((p["employee_id"], p["first_name"], p["last_name"],
                     p["department"], p["team"], p["start_date"], p["ip"]))

    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(HEADER)
        w.writerows(rows)

    if args.parquet:
        import pyarrow as pa
        import pyarrow.parquet as pq
        cols = list(zip(*rows))
        table = pa.table({name: pa.array(col, pa.string())
                          for name, col in zip(HEADER, cols)})
        pq.write_table(table, args.parquet, compression="snappy",
                       row_group_size=100_000)

    # ---- summary -----------------------------------------------------------
    size = os.path.getsize(args.out) / 1e6
    print(f"wrote {args.out}: {len(rows):,} rows x {len(HEADER)} cols ({size:.1f} MB)")
    print(f"  Employee_ID : 0000001 .. {I.employee_id_str(total)}")
    print(f"  IP space    : {I.CLIENT_NET} "
          f"({len(rows):,} assigned of {I.CLIENT_NET.num_addresses - 2:,} hosts)")
    print(f"  Start_Date  : {I.HIRE_START} .. {I.HIRE_END}")
    if args.parquet:
        print(f"  parquet     : {args.parquet} "
              f"({os.path.getsize(args.parquet) / 1e6:.1f} MB)")

    print("\n  Department distribution")
    for d, _ in I.DEPARTMENTS:
        c = dept_counts.get(d, 0)
        print(f"    {d:<12} {c:>7,} {c / len(rows) * 100:5.2f}%")

    print("\n  Team distribution (% within department)")
    for d, _ in I.DEPARTMENTS:
        for team, _w in I.TEAMS[d]:
            c = team_counts.get((d, team), 0)
            within = c / dept_counts[d] * 100 if dept_counts.get(d) else 0
            print(f"    {d:<12} {team:<24} {c:>6,} {within:5.2f}%")


    if args.s3:
        if S3 is None:
            sys.exit("--s3 requires garage_s3.py next to this script")
        print()
        S3.push(args, files=[args.out, args.parquet])


if __name__ == "__main__":
    main()
