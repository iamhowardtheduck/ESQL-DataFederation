#!/usr/bin/env bash
#
# install-seaweedfs.sh — Single-node SeaweedFS installer, NO ROOT REQUIRED.
#
# Drop-in alternative to install-garage.sh: same S3 endpoint (:9000), same
# credentials, same bucket, same data-generation stage and final screen, so
# the V2 generators and any downstream Elasticsearch config work unchanged.
#
# Everything lives under the invoking user's home directory:
#
#   ~/.local/bin/weed             server binary (master+volume+filer+S3 in one)
#   ~/seaweedfs/s3.config.json    S3 identities (REQUIRED — without it,
#                                 SeaweedFS accepts ANY key as admin)
#   ~/seaweedfs/data              object data (master + volume)
#   ~/seaweedfs/seaweedctl        start/stop/status/logs/shell helper
#   ~/seaweedfs/seaweed.log       server log
#
# Ports (all unprivileged):
#   9000  S3 API          (drop-in for MinIO/Garage)
#   8888  WEB UI          weed admin console, http://<host>:8888/ — SAME login
#                         as the S3 bucket (minioadmin / S3 secret key)
#   9333  Master UI/API   cluster status page (unauthenticated; firewall it)
#   8889  Filer           internal (dir listing disabled)
#   8080  Volume server   internal data transport
#
# Usage: ./install-seaweedfs.sh
#        SKIP_DATAGEN=1 ./install-seaweedfs.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
S3_ACCESS_KEY="minioadmin"                      # kept for MinIO drop-in compat
S3_SECRET_KEY='datafederation_hooray!'
S3_BUCKET="datafederation"

BASE_DIR="${SEAWEED_HOME:-$HOME/seaweedfs}"
DATA_DIR="${BASE_DIR}/data"
S3_CONF="${BASE_DIR}/s3.config.json"
LOG_FILE="${BASE_DIR}/seaweed.log"
PID_FILE="${BASE_DIR}/seaweed.pid"
CTL="${BASE_DIR}/seaweedctl"

S3_PORT="9000"                                  # S3 API (same as MinIO/Garage)
ADMIN_PORT="8888"                               # authenticated web UI (weed admin)
FILER_PORT="8889"                               # filer (internal; no public UI)
MASTER_PORT="9333"                              # master UI/API
VOLUME_PORT="8080"                              # volume server
ADMIN_DIR="${BASE_DIR}/admin"                   # admin console state
ADMIN_PID_FILE="${BASE_DIR}/admin.pid"
S3_REGION="garage"                              # SeaweedFS accepts any region;
                                                # kept as 'garage' so garage_s3.py
                                                # defaults keep working unchanged

# Release to install: a tag from https://github.com/seaweedfs/seaweedfs/releases
SEAWEED_VERSION="4.45"
WEED_BIN="${HOME}/.local/bin/weed"

# Data generators (gen_*.py + identity.py + garage_s3.py). If the directory
# exists, the installer runs them with --s3 after SeaweedFS is healthy.
# Set SKIP_DATAGEN=1 in the environment to install SeaweedFS only.
GEN_DIR="/home/elastic/ESQL-DataFederation/Scripts/V2/Garage"
GEN_OUT_DIR="${GEN_DIR}/output"                 # local artifacts land here
TXN_ROWS="${TXN_ROWS:-1000000}"                 # gen_parquet.py --rows
LOG_ROWS="${LOG_ROWS:-500000}"                  # gen_parquet_logs.py --rows
ORDER_ROWS="${ORDER_ROWS:-500000}"              # gen_parquet_orders.py --rows

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Dependency check (no root -> we can verify, not install)
# ---------------------------------------------------------------------------
log "Checking prerequisites"
MISSING=()
for c in curl openssl python3 tar; do
  command -v "$c" >/dev/null || MISSING+=("$c")
done
[[ ${#MISSING[@]} -eq 0 ]] \
  || die "Missing required tools: ${MISSING[*]} (ask an admin to install them)"
if ! python3 -m pip --version >/dev/null 2>&1; then
  warn "pip not found — attempting ensurepip --user"
  python3 -m ensurepip --user >/dev/null 2>&1 \
    || warn "ensurepip failed; data generation will fail without pip"
fi

# ---------------------------------------------------------------------------
# 2. Architecture detection
# ---------------------------------------------------------------------------
case "$(uname -m)" in
  x86_64)  WEED_ARCH="linux_amd64" ;;
  aarch64) WEED_ARCH="linux_arm64" ;;
  *) die "Unsupported architecture: $(uname -m)" ;;
esac
log "Detected architecture: ${WEED_ARCH}"

WEED_URL="https://github.com/seaweedfs/seaweedfs/releases/download/${SEAWEED_VERSION}/${WEED_ARCH}.tar.gz"

# ---------------------------------------------------------------------------
# 3. Binary
# ---------------------------------------------------------------------------
log "Downloading SeaweedFS ${SEAWEED_VERSION} -> ${WEED_BIN}"
mkdir -p "$(dirname "$WEED_BIN")" "$BASE_DIR" "$DATA_DIR" "$ADMIN_DIR"
# stop previous instances before replacing the binary — and WAIT for full
# exit, or the new filer can't take over the metadata store and sockets
for PF in "$ADMIN_PID_FILE" "$PID_FILE"; do
  if [[ -f "$PF" ]] && kill -0 "$(cat "$PF")" 2>/dev/null; then
    OLD_PID="$(cat "$PF")"
    log "Stopping running process (pid ${OLD_PID})"
    kill "$OLD_PID" 2>/dev/null || true
    for _ in $(seq 1 30); do kill -0 "$OLD_PID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$OLD_PID" 2>/dev/null; then kill -9 "$OLD_PID" 2>/dev/null; sleep 2; fi
    rm -f "$PF"
  fi
done
TMP_TGZ="$(mktemp /tmp/weed.XXXXXX.tar.gz)"
curl -fsSL --retry 3 -o "$TMP_TGZ" "$WEED_URL" \
  || die "Download failed: $WEED_URL"
tar -xzf "$TMP_TGZ" -C "$(dirname "$WEED_BIN")" weed \
  || die "Could not extract weed binary"
rm -f "$TMP_TGZ"
chmod 755 "$WEED_BIN"
"$WEED_BIN" version | head -n1

# ---------------------------------------------------------------------------
# 4. S3 credentials config
# ---------------------------------------------------------------------------
# REQUIRED: without -s3.config, SeaweedFS accepts any access/secret key with
# full admin rights. This file pins access to the workshop identity.
log "Writing ${S3_CONF}"
cat > "$S3_CONF" <<EOF
{
  "identities": [
    {
      "name": "workshop-admin",
      "credentials": [
        { "accessKey": "${S3_ACCESS_KEY}", "secretKey": "${S3_SECRET_KEY}" }
      ],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    }
  ]
}
EOF
chmod 600 "$S3_CONF"

# ---------------------------------------------------------------------------
# 5. seaweedctl — start/stop/status/logs/shell helper (replaces systemd)
# ---------------------------------------------------------------------------
log "Writing ${CTL}"
cat > "$CTL" <<EOF
#!/usr/bin/env bash
# seaweedctl — manage the rootless SeaweedFS instance. Managed by install-seaweedfs.sh
set -u
BIN="${WEED_BIN}"
BASE="${BASE_DIR}"
LOG="${LOG_FILE}"
PID="${PID_FILE}"
APID="${ADMIN_PID_FILE}"
ALOG="${BASE_DIR}/admin.log"

running()       { [[ -f "\$PID" ]] && kill -0 "\$(cat "\$PID")" 2>/dev/null; }
admin_running() { [[ -f "\$APID" ]] && kill -0 "\$(cat "\$APID")" 2>/dev/null; }

stop_pidfile() {  # \$1 = pidfile, \$2 = name
  local pf="\$1" name="\$2" p
  if [[ -f "\$pf" ]] && kill -0 "\$(cat "\$pf")" 2>/dev/null; then
    p="\$(cat "\$pf")"
    kill "\$p" 2>/dev/null
    for _ in \$(seq 1 30); do kill -0 "\$p" 2>/dev/null || break; sleep 1; done
    kill -0 "\$p" 2>/dev/null && { kill -9 "\$p" 2>/dev/null; sleep 1; }
    echo "\$name stopped"
  else
    echo "\$name not running"
  fi
  rm -f "\$pf"
}

case "\${1:-status}" in
  start)
    cd "\$BASE"
    if running; then
      echo "seaweedfs already running (pid \$(cat "\$PID"))"
    else
      nohup "\$BIN" server \\
          -dir="${DATA_DIR}" \\
          -ip.bind=0.0.0.0 \\
          -master.port=${MASTER_PORT} \\
          -volume.port=${VOLUME_PORT} \\
          -filer -filer.port=${FILER_PORT} -filer.disableDirListing \\
          -s3 -s3.port=${S3_PORT} -s3.config="${S3_CONF}" \\
          >> "\$LOG" 2>&1 &
      echo \$! > "\$PID"
      echo "seaweedfs started (pid \$(cat "\$PID"))"
    fi
    if admin_running; then
      echo "admin ui already running (pid \$(cat "\$APID"))"
    else
      # same login as the S3 bucket
      nohup "\$BIN" admin \\
          -port=${ADMIN_PORT} \\
          -master="localhost:${MASTER_PORT}" \\
          -dataDir="${ADMIN_DIR}" \\
          -adminUser="${S3_ACCESS_KEY}" \\
          -adminPassword='${S3_SECRET_KEY}' \\
          >> "\$ALOG" 2>&1 &
      echo \$! > "\$APID"
      echo "admin ui started (pid \$(cat "\$APID"))"
    fi
    ;;
  stop)
    stop_pidfile "\$APID" "admin ui"
    stop_pidfile "\$PID" "seaweedfs"
    ;;
  restart) "\$0" stop; sleep 2; "\$0" start ;;
  status)
    RC=0
    if running; then echo "seaweedfs running (pid \$(cat "\$PID"))"; else echo "seaweedfs not running"; RC=1; fi
    if admin_running; then echo "admin ui running (pid \$(cat "\$APID"))"; else echo "admin ui not running"; RC=1; fi
    exit \$RC
    ;;
  logs)  tail -f "\$LOG" "\$ALOG" ;;
  shell) exec "\$BIN" shell -master="localhost:${MASTER_PORT}" ;;
  *) echo "usage: seaweedctl {start|stop|restart|status|logs|shell}"; exit 2 ;;
esac
EOF
chmod 755 "$CTL"

# survive reboots via the user's crontab, when crontab is available
if command -v crontab >/dev/null; then
  CRON_LINE="@reboot ${CTL} start"
  if ! crontab -l 2>/dev/null | grep -Fq "$CRON_LINE"; then
    ( crontab -l 2>/dev/null; echo "$CRON_LINE" ) | crontab - 2>/dev/null \
      && log "Added @reboot crontab entry" \
      || warn "Could not modify crontab — restart manually after reboot: ${CTL} start"
  fi
else
  warn "crontab unavailable — restart manually after reboot: ${CTL} start"
fi

# ---------------------------------------------------------------------------
# 6. Start + health check
# ---------------------------------------------------------------------------
log "Starting SeaweedFS"
"$CTL" start

s3_up() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${S3_PORT}/" || true)"
  [[ "$code" != "000" ]]
}
for _ in {1..45}; do
  ADMIN_CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${ADMIN_PORT}/" || true)"
  if curl -fsS "http://127.0.0.1:${MASTER_PORT}/cluster/status" >/dev/null 2>&1 \
     && s3_up \
     && [[ "$ADMIN_CODE" != "000" ]]; then
    READY=1; break
  fi
  sleep 1
done
[[ "${READY:-0}" == "1" ]] || {
  tail -n 40 "$LOG_FILE"
  die "SeaweedFS did not become healthy — see the log above"
}

# ---------------------------------------------------------------------------
# 7. Create the bucket
# ---------------------------------------------------------------------------
log "Creating bucket '${S3_BUCKET}'"
printf 's3.bucket.create -name %s\n' "$S3_BUCKET" \
  | "$WEED_BIN" shell -master="localhost:${MASTER_PORT}" >/dev/null 2>&1 \
  || warn "weed shell bucket create failed (the generators create it on upload anyway)"

# ---------------------------------------------------------------------------
# 8. Synthetic data generation -> SeaweedFS
# ---------------------------------------------------------------------------
# Runs the V2 generators with --s3. Their built-in defaults already match this
# installer (endpoint :9000, creds above, bucket datafederation; SeaweedFS
# accepts the 'garage' region string), so no extra wiring is needed.
# Local copies of every artifact are kept in ${GEN_OUT_DIR}.
if [[ "${SKIP_DATAGEN:-0}" == "1" ]]; then
  warn "SKIP_DATAGEN=1 — skipping data generation"
elif [[ ! -d "$GEN_DIR" ]]; then
  warn "Generator directory not found: ${GEN_DIR} — skipping data generation"
else
  for f in identity.py garage_s3.py gen_hr_csv.py gen_parquet.py \
           gen_parquet_logs.py gen_parquet_orders.py; do
    [[ -f "${GEN_DIR}/${f}" ]] || die "Missing ${GEN_DIR}/${f}"
  done

  log "Installing Python dependencies (boto3, pyarrow) to user site"
  python3 -m pip install --user --break-system-packages -q boto3 pyarrow \
    || python3 -m pip install --user -q boto3 pyarrow \
    || die "pip install failed"

  mkdir -p "$GEN_OUT_DIR"
  cd "$GEN_OUT_DIR"
  DG_HR="$(mktemp)"; DG_TXN="$(mktemp)"; DG_LOGS="$(mktemp)"; DG_ORD="$(mktemp)"

  log "Generating HR roster (${GEN_DIR}/gen_hr_csv.py)"
  python3 "${GEN_DIR}/gen_hr_csv.py" --parquet hr_roster.parquet --s3 2>&1 \
    | tee "$DG_HR" || die "gen_hr_csv.py failed"

  log "Creating gzip tarball: hr_roster.csv.tar.gz"
  tar -czf hr_roster.csv.tar.gz hr_roster.csv \
    || die "tar failed"
  python3 - <<PYEOF || die "tar.gz upload failed"
import boto3
from botocore.config import Config
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:${S3_PORT}",
                  region_name="${S3_REGION}",
                  aws_access_key_id="${S3_ACCESS_KEY}",
                  aws_secret_access_key="${S3_SECRET_KEY}",
                  config=Config(s3={"addressing_style": "path"}))
s3.upload_file("hr_roster.csv.tar.gz", "${S3_BUCKET}",
               "hr/hr_roster.csv.tar.gz")
print("  s3        : s3://${S3_BUCKET}/hr/hr_roster.csv.tar.gz")
PYEOF

  log "Generating transaction archive (${TXN_ROWS} rows — this takes a while)"
  python3 "${GEN_DIR}/gen_parquet.py" --rows "$TXN_ROWS" --s3 2>&1 \
    | tee "$DG_TXN" || die "gen_parquet.py failed"

  log "Generating application logs (${LOG_ROWS} rows)"
  python3 "${GEN_DIR}/gen_parquet_logs.py" --rows "$LOG_ROWS" --s3 2>&1 \
    | tee "$DG_LOGS" || die "gen_parquet_logs.py failed"

  log "Generating order documents (${ORDER_ROWS} rows, NDJSON)"
  python3 "${GEN_DIR}/gen_parquet_orders.py" --rows "$ORDER_ROWS" --ndjson-only --s3 2>&1 \
    | tee "$DG_ORD" || die "gen_parquet_orders.py failed"

  cd - >/dev/null
  DATAGEN_DONE=1
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
HOSTN="$(hostname -s 2>/dev/null || hostname)"
ENDPOINT="http://${HOSTN}:${S3_PORT}"
WEBUI="http://${HOSTN}:${ADMIN_PORT}"

# Full install details are kept out of the final screen but preserved:
SUMMARY_FILE="${BASE_DIR}/install-summary.txt"
cat > "$SUMMARY_FILE" <<EOF
SeaweedFS rootless install — $(date -u +%Y-%m-%dT%H:%M:%SZ)
S3 API       : ${ENDPOINT} (path-style; any region string accepted)
Web UI       : ${WEBUI}/  (login: same as S3 — access key / secret key)
Master UI    : http://${HOSTN}:${MASTER_PORT}/ (unauthenticated)
Access key   : ${S3_ACCESS_KEY}
Secret key   : ${S3_SECRET_KEY}
Bucket       : ${S3_BUCKET}
Data dir     : ${DATA_DIR}
S3 identities: ${S3_CONF}
Service      : ${CTL} {start|stop|restart|status|logs|shell}
NOTE: the master UI (:${MASTER_PORT}), filer (:${FILER_PORT}) and volume
      (:${VOLUME_PORT}) ports are unauthenticated internals — restrict them
      at the firewall/security group; only :${S3_PORT} and :${ADMIN_PORT}
      need to be reachable remotely.
EOF
chmod 600 "$SUMMARY_FILE"

if [[ "${DATAGEN_DONE:-0}" != "1" ]]; then
  warn "Data generation did not run (see warnings above)."
  warn "SeaweedFS itself is up — details in ${SUMMARY_FILE}"
  exit 0
fi

# Pull the real counts/windows from the generators' own output, with fallbacks.
HR_COUNT="$(grep -oE 'wrote hr_roster\.csv: [0-9,]+' "$DG_HR" | grep -oE '[0-9,]+$' || echo '?')"
TXN_WINDOW="$(grep -oE 'window[[:space:]]*: [0-9-]+ \.\. [0-9-]+' "$DG_TXN" | head -1 | sed 's/window[[:space:]]*: //' || true)"
ORD_WINDOW="$(grep -oE 'window[[:space:]]*: [0-9-]+ \.\. [0-9-]+' "$DG_ORD" | head -1 | sed 's/window[[:space:]]*: //' || true)"
TXN_WINDOW="${TXN_WINDOW:-last 7 years}"
ORD_WINDOW="${ORD_WINDOW:-last 2 years}"
rm -f "$DG_HR" "$DG_TXN" "$DG_LOGS" "$DG_ORD"

# Final screen
clear 2>/dev/null || printf '\033c'
cat <<EOF

 Datasets generated in SeaweedFS (bucket: ${S3_BUCKET})
 ─────────────────────────────────────────────────────────────────────────────
 1. HR roster       CSV + Parquet   ${HR_COUNT} docs   current snapshot
                    s3://${S3_BUCKET}/hr/hr_roster.csv
                    s3://${S3_BUCKET}/hr/hr_roster.csv.tar.gz (gzip copy)
                    s3://${S3_BUCKET}/hr/hr_roster.parquet
 2. Transactions    Parquet         ${TXN_ROWS} docs   ${TXN_WINDOW}
                    s3://${S3_BUCKET}/transactions/**/*.parquet
 3. App logs        Parquet         ${LOG_ROWS} docs   last 30 days
                    s3://${S3_BUCKET}/logs/app_logs.parquet
 4. Orders          NDJSON          ${ORDER_ROWS} docs   ${ORD_WINDOW}
                    s3://${S3_BUCKET}/orders/orders.ndjson
 ─────────────────────────────────────────────────────────────────────────────
 Endpoint   : ${ENDPOINT}
 Region     : ${S3_REGION}
 Access key : ${S3_ACCESS_KEY}
 Secret key : ${S3_SECRET_KEY}
 Web UI     : ${WEBUI}/  (login with the access key + secret key above)

You are now ready to begin the assignment.

EOF
