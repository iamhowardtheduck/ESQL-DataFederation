#!/usr/bin/env bash
#
# seed-garage.sh — Generate the workshop datasets and upload them to Garage.
#
# WORKSHOP STEP. Run as the workshop user (no root). Requires that
# install-garage.sh has already been run on this host (at provisioning).
#
# Runs the V2 generators in this directory with --s3:
#   gen_hr_csv.py           -> s3://<bucket>/hr/            (CSV, tar.gz, Parquet)
#   gen_parquet.py          -> s3://<bucket>/transactions/  (partitioned Parquet)
#   gen_parquet_logs.py     -> s3://<bucket>/logs/          (Parquet)
#   gen_parquet_orders.py   -> s3://<bucket>/orders/        (NDJSON)
# Local copies of every artifact are kept in ./output next to this script.
#
# Usage:  bash seed-garage.sh
# Env overrides: TXN_ROWS, LOG_ROWS, ORDER_ROWS, GARAGE_HOME, PYTHON
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (must match install-garage.sh / garage_s3.py defaults)
# ---------------------------------------------------------------------------
GARAGE_ACCESS_KEY="minioadmin"
GARAGE_SECRET_KEY='datafederation_hooray!'
GARAGE_BUCKET="datafederation"
GARAGE_S3_PORT="9000"
GARAGE_ADMIN_PORT="3903"
GARAGE_REGION="garage"

BASE_DIR="${GARAGE_HOME:-$HOME/garage}"          # where install-garage.sh put things
CTL="${BASE_DIR}/garagectl"

GEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # this directory
GEN_OUT_DIR="${GEN_DIR}/output"                   # local artifacts land here
REPO_ROOT="$(cd "${GEN_DIR}/../../.." && pwd)"    # Scripts/V2/Garage -> repo root
VENV_PY="${REPO_ROOT}/.venv/bin/python"           # created by the host setup script

TXN_ROWS="${TXN_ROWS:-1000000}"                   # gen_parquet.py --rows
LOG_ROWS="${LOG_ROWS:-500000}"                    # gen_parquet_logs.py --rows
ORDER_ROWS="${ORDER_ROWS:-500000}"                # gen_parquet_orders.py --rows

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] && warn "Running as root — generated files will be root-owned. Prefer running as the workshop user."

# ---------------------------------------------------------------------------
# 1. Generators present?
# ---------------------------------------------------------------------------
for f in identity.py garage_s3.py gen_hr_csv.py gen_parquet.py \
         gen_parquet_logs.py gen_parquet_orders.py; do
  [[ -f "${GEN_DIR}/${f}" ]] || die "Missing ${GEN_DIR}/${f}"
done

# ---------------------------------------------------------------------------
# 2. Python + dependencies (boto3, pyarrow)
# ---------------------------------------------------------------------------
# Prefer the repo venv from the setup script; fall back to system python3.
if [[ -n "${PYTHON:-}" ]]; then
  PY="$PYTHON"
elif [[ -x "$VENV_PY" ]]; then
  PY="$VENV_PY"
else
  PY="$(command -v python3)" || die "python3 not found"
fi
log "Using Python: ${PY}"

if ! "$PY" -c "import boto3, pyarrow" >/dev/null 2>&1; then
  log "Installing Python dependencies (boto3, pyarrow)"
  if [[ "$PY" == "$VENV_PY" ]]; then
    "$PY" -m pip install -q boto3 pyarrow \
      || die "pip install into ${REPO_ROOT}/.venv failed (is it writable?). Try: ${PY} -m pip install boto3 pyarrow"
  else
    "$PY" -m pip install --user --break-system-packages -q boto3 pyarrow \
      || "$PY" -m pip install --user -q boto3 pyarrow \
      || die "pip install failed"
  fi
fi

# ---------------------------------------------------------------------------
# 3. Garage up?
# ---------------------------------------------------------------------------
healthy() { curl -fsS "http://127.0.0.1:${GARAGE_ADMIN_PORT}/health" >/dev/null 2>&1; }

if ! healthy; then
  [[ -x "$CTL" ]] || die "Garage is not running and ${CTL} not found — was install-garage.sh run on this host?"
  log "Garage not responding — starting it"
  "$CTL" start
  for _ in {1..30}; do healthy && break; sleep 1; done
  healthy || { "$CTL" logs 2>/dev/null | tail -n 40 || true; die "Garage did not become healthy"; }
fi
log "Garage is healthy at http://127.0.0.1:${GARAGE_S3_PORT}"

# ---------------------------------------------------------------------------
# 4. Synthetic data generation -> Garage
# ---------------------------------------------------------------------------
# The generators' built-in defaults already match the installer (endpoint
# :9000, region garage, bucket datafederation, creds above), so no extra
# wiring is needed — garage_s3.py next to the generators does the upload.
mkdir -p "$GEN_OUT_DIR"
cd "$GEN_OUT_DIR"

DG_HR="$(mktemp)"; DG_TXN="$(mktemp)"; DG_LOGS="$(mktemp)"; DG_ORD="$(mktemp)"
trap 'rm -f "$DG_HR" "$DG_TXN" "$DG_LOGS" "$DG_ORD"' EXIT

log "Generating HR roster (gen_hr_csv.py)"
"$PY" "${GEN_DIR}/gen_hr_csv.py" --parquet hr_roster.parquet --s3 2>&1 \
  | tee "$DG_HR" || die "gen_hr_csv.py failed"

log "Creating gzip tarball: hr_roster.csv.tar.gz"
tar -czf hr_roster.csv.tar.gz hr_roster.csv || die "tar failed"
"$PY" - <<PYEOF || die "tar.gz upload failed"
import boto3
from botocore.config import Config
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:${GARAGE_S3_PORT}",
                  region_name="${GARAGE_REGION}",
                  aws_access_key_id="${GARAGE_ACCESS_KEY}",
                  aws_secret_access_key="${GARAGE_SECRET_KEY}",
                  config=Config(s3={"addressing_style": "path"}))
s3.upload_file("hr_roster.csv.tar.gz", "${GARAGE_BUCKET}",
               "hr/hr_roster.csv.tar.gz")
print("  s3       : s3://${GARAGE_BUCKET}/hr/hr_roster.csv.tar.gz")
PYEOF

log "Generating transaction archive (${TXN_ROWS} rows — this takes a while)"
"$PY" "${GEN_DIR}/gen_parquet.py" --rows "$TXN_ROWS" --s3 2>&1 \
  | tee "$DG_TXN" || die "gen_parquet.py failed"

log "Generating application logs (${LOG_ROWS} rows)"
"$PY" "${GEN_DIR}/gen_parquet_logs.py" --rows "$LOG_ROWS" --s3 2>&1 \
  | tee "$DG_LOGS" || die "gen_parquet_logs.py failed"

log "Generating order documents (${ORDER_ROWS} rows, NDJSON)"
"$PY" "${GEN_DIR}/gen_parquet_orders.py" --rows "$ORDER_ROWS" --ndjson-only --s3 2>&1 \
  | tee "$DG_ORD" || die "gen_parquet_orders.py failed"

cd - >/dev/null

# ---------------------------------------------------------------------------
# 5. Final screen
# ---------------------------------------------------------------------------
HOSTN="$(hostname -s 2>/dev/null || hostname)"
ENDPOINT="http://${HOSTN}:${GARAGE_S3_PORT}"

# Pull the real counts/windows from the generators' own output, with fallbacks.
HR_COUNT="$(grep -oE 'wrote hr_roster\.csv: [0-9,]+' "$DG_HR" | grep -oE '[0-9,]+$' || echo '?')"
TXN_WINDOW="$(grep -oE 'window[[:space:]]*: [0-9-]+ \.\. [0-9-]+' "$DG_TXN" | head -1 | sed 's/window[[:space:]]*: //' || true)"
ORD_WINDOW="$(grep -oE 'window[[:space:]]*: [0-9-]+ \.\. [0-9-]+' "$DG_ORD" | head -1 | sed 's/window[[:space:]]*: //' || true)"
TXN_WINDOW="${TXN_WINDOW:-last 7 years}"
ORD_WINDOW="${ORD_WINDOW:-last 2 years}"

clear 2>/dev/null || printf '\033c'
cat <<EOF

  Datasets generated in Garage (bucket: ${GARAGE_BUCKET})
  ─────────────────────────────────────────────────────────────────────────────
  1. HR roster        CSV + Parquet   ${HR_COUNT} docs        current snapshot
       s3://${GARAGE_BUCKET}/hr/hr_roster.csv
       s3://${GARAGE_BUCKET}/hr/hr_roster.csv.tar.gz   (gzip copy)
       s3://${GARAGE_BUCKET}/hr/hr_roster.parquet
  2. Transactions     Parquet         ${TXN_ROWS} docs   ${TXN_WINDOW}
       s3://${GARAGE_BUCKET}/transactions/**/*.parquet
  3. App logs         Parquet         ${LOG_ROWS} docs    last 30 days
       s3://${GARAGE_BUCKET}/logs/app_logs.parquet
  4. Orders           NDJSON          ${ORDER_ROWS} docs    ${ORD_WINDOW}
       s3://${GARAGE_BUCKET}/orders/orders.ndjson
  ─────────────────────────────────────────────────────────────────────────────
  Endpoint   : ${ENDPOINT}
  Region     : ${GARAGE_REGION}
  Access key : ${GARAGE_ACCESS_KEY}
  Secret key : ${GARAGE_SECRET_KEY}

  You are now ready to begin the assignment.

EOF
