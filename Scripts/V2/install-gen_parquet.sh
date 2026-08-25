#!/usr/bin/env bash
#
# install-gen_parquet.sh — generate the workshop datasets and load them into
# MinIO for ES|QL Data Federation.
#
# WHAT CHANGED vs the original installer
#   * identity.py is now REQUIRED next to the generators (it is the shared
#     source of truth for the 20,025 employees, the 50M account space, the
#     10.49.0.0/17 client range, and the two fraud narratives). Make sure it
#     is committed to Scripts/ — every generator asserts IDENTITY_VERSION.
#   * gen_parquet.py --rows was raised from 50000. The account space grew from
#     35k to 50M and all 20,025 employees are now GUARANTEED events, so 50k
#     rows left almost nothing for the general population. 2M is a good
#     workshop default (~68s, ~120 MB). Raise TX_ROWS for a denser archive.
#   * The transactions copy now matches the partitioned output directory
#     (transactions_history/), instead of a transactions.parquet that the
#     default run never produced.
#   * faker is no longer needed by these four generators (kept in the pip line
#     only if your other SDG scripts still use it).
#
set -Eeuo pipefail

SCRIPTS_DIR="/home/elastic/ESQL-DataFederation/Scripts/V2"
MC_ALIAS="local"
MC_URL="http://localhost:9000"
MC_USER="minioadmin"
MC_PASS='datafederation_hooray!'

# ---- tunables --------------------------------------------------------------
TX_ROWS="${TX_ROWS:-2000000}"        # historical transaction rows
LOG_ROWS="${LOG_ROWS:-1000000}"      # application-log rows
LOG_DAYS="${LOG_DAYS:-30}"
SUSPICIOUS_RATE="${SUSPICIOUS_RATE:-0.06}"
CAMPAIGNS="${CAMPAIGNS:-6}"
ORDER_ROWS="${ORDER_ROWS:-50000}"

cd "$SCRIPTS_DIR"

# identity.py is mandatory — fail loudly rather than halfway through.
if [[ ! -f identity.py ]]; then
  echo "ERROR: identity.py is missing from $SCRIPTS_DIR." >&2
  echo "       All generators depend on it. Commit/copy it here first." >&2
  exit 1
fi

# ---- python env ------------------------------------------------------------
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install pandas numpy elasticsearch pyarrow    # add 'faker' if other scripts need it

PY="$SCRIPTS_DIR/.venv/bin/python"

# ---- MinIO bucket ----------------------------------------------------------
mc alias set "$MC_ALIAS" "$MC_URL" "$MC_USER" "$MC_PASS"
mc admin info "$MC_ALIAS"
mc mb --ignore-existing "$MC_ALIAS/datasets"

# ---- 1) transactions (hive-partitioned year=/month=) -----------------------
# Employees (49,000,001..49,020,025) are covered automatically; the securities
# -fraud employee 0011209 and the county-structuring account 23,114,007 are
# injected here. --single instead if you prefer one flat file.
"$PY" gen_parquet.py --rows "$TX_ROWS" --out-dir transactions_history
mc cp --recursive transactions_history/ "$MC_ALIAS/datasets/transactions/"

# ---- 2) application logs (10.49.0.0/17, Employee_ID in web paths) -----------
"$PY" gen_parquet_logs.py --rows "$LOG_ROWS" --days "$LOG_DAYS" \
      --suspicious-rate "$SUSPICIOUS_RATE" --campaigns "$CAMPAIGNS"
mc cp --recursive app_logs.parquet "$MC_ALIAS/datasets/logs/"

# ---- 3) HR roster (20,025 employees; join key for clientIp / employee_id) --
# NOTE: columns are now Employee_ID, First_Name, Last_Name, Department, Team,
# Start_Date, IP_Address (Team replaces Sub-Department). Update any enrich
# policy or ES|QL that referenced the old column names.
"$PY" gen_hr_csv.py --out hr_roster.csv
mc cp hr_roster.csv "$MC_ALIAS/datasets/hr/"

# ---- 4) orders (nested JSON) -----------------------------------------------
"$PY" gen_parquet_orders.py --rows "$ORDER_ROWS" --ndjson orders.ndjson
mc cp orders.ndjson "$MC_ALIAS/datasets/orders/"

mc ls -r "$MC_ALIAS/datasets/"

clear
echo ""
echo "Generated transactions and logs as parquet, HR roster as CSV, orders as ndjson."
echo "  transactions : $TX_ROWS rows  (50M account space, all 20,025 employees covered)"
echo "  logs         : $LOG_ROWS rows over $LOG_DAYS days, client IPs in 10.49.0.0/17"
echo "  narratives   : securities fraud emp 0011209 (Finance > Stock_Administration)"
echo "                 + county structuring acct 23,114,007"
echo ""
echo "You are now ready to begin the assignment."
echo ""
