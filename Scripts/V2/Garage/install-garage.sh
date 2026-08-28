#!/usr/bin/env bash
#
# install-garage.sh — Single-node Garage installer, NO ROOT REQUIRED.
#
# Everything lives under the invoking user's home directory:
#
#   ~/.local/bin/garage       server binary
#   ~/garage/garage.toml      configuration
#   ~/garage/meta, ~/garage/data
#   ~/garage/garagectl        start/stop/status/logs helper
#   ~/garage/garage.log       server log (garagectl logs)
#
# The server runs as this user via nohup (no systemd, no service account,
# no /etc, no ufw). A crontab @reboot entry restarts it after a reboot when
# the user's crontab is available. Ports 9000/3901/3903 are unprivileged.
#
# After Garage is healthy, the V2 data generators are run with --s3 to seed
# the bucket (skip with SKIP_DATAGEN=1).
#
# Usage: ./install-garage.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GARAGE_ACCESS_KEY="minioadmin"                  # kept for MinIO drop-in compat
GARAGE_SECRET_KEY='datafederation_hooray!'
GARAGE_BUCKET="datafederation"                  # default bucket created at boot

BASE_DIR="${GARAGE_HOME:-$HOME/garage}"         # everything Garage lives here
GARAGE_META_DIR="${BASE_DIR}/meta"
GARAGE_DATA_DIR="${BASE_DIR}/data"
CONFIG_FILE="${BASE_DIR}/garage.toml"
LOG_FILE="${BASE_DIR}/garage.log"
PID_FILE="${BASE_DIR}/garage.pid"
CTL="${BASE_DIR}/garagectl"

GARAGE_S3_PORT="9000"                           # S3 API endpoint (same as MinIO)
GARAGE_RPC_PORT="3901"                          # inter-node RPC (loopback only)
GARAGE_ADMIN_PORT="3903"                        # admin API + metrics
GARAGE_BIND_ADDR="0.0.0.0"                      # S3/admin listen on all interfaces
GARAGE_REGION="garage"                          # S3 region name clients must use

# Release to install. Pin a tag from https://garagehq.deuxfleurs.fr/download/
GARAGE_VERSION="v2.3.0"                         # requires >= v2.3.0 for --single-node
GARAGE_BIN="${HOME}/.local/bin/garage"

# Data generators (gen_*.py + identity.py + garage_s3.py). If the directory
# exists, the installer runs them with --s3 after Garage is healthy.
# Set SKIP_DATAGEN=1 in the environment to install Garage only.
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
for c in curl openssl python3; do
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
  x86_64)  TRIPLE="x86_64-unknown-linux-musl"  ;;
  aarch64) TRIPLE="aarch64-unknown-linux-musl" ;;
  *) die "Unsupported architecture: $(uname -m)" ;;
esac
log "Detected architecture: ${TRIPLE}"

GARAGE_URL="https://garagehq.deuxfleurs.fr/_releases/${GARAGE_VERSION}/${TRIPLE}/garage"

# ---------------------------------------------------------------------------
# 3. Binary
# ---------------------------------------------------------------------------
log "Downloading Garage server (${GARAGE_VERSION}) -> ${GARAGE_BIN}"
mkdir -p "$(dirname "$GARAGE_BIN")" "$BASE_DIR" \
         "$GARAGE_META_DIR" "$GARAGE_DATA_DIR"
# stop a previous instance before replacing the binary
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  log "Stopping running Garage instance"
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
  sleep 2
fi
curl -fsSL --retry 3 -o "${GARAGE_BIN}.tmp" "$GARAGE_URL" \
  || die "Download failed: $GARAGE_URL"
chmod 755 "${GARAGE_BIN}.tmp"
mv -f "${GARAGE_BIN}.tmp" "$GARAGE_BIN"
"$GARAGE_BIN" --version | head -n1

# ---------------------------------------------------------------------------
# 4. Configuration
# ---------------------------------------------------------------------------
# Reuse secrets across re-runs if a config already exists, otherwise generate.
if [[ -f "$CONFIG_FILE" ]] && grep -q '^rpc_secret' "$CONFIG_FILE"; then
  RPC_SECRET="$(awk -F'"' '/^rpc_secret/ {print $2}' "$CONFIG_FILE")"
  log "Reusing existing rpc_secret from ${CONFIG_FILE}"
else
  RPC_SECRET="$(openssl rand -hex 32)"
fi
ADMIN_TOKEN="$(openssl rand -hex 32)"

log "Writing ${CONFIG_FILE}"
cat > "$CONFIG_FILE" <<EOF
# Garage configuration — managed by install-garage.sh (rootless)
metadata_dir = "${GARAGE_META_DIR}"
data_dir = "${GARAGE_DATA_DIR}"

replication_factor = 1

rpc_bind_addr = "127.0.0.1:${GARAGE_RPC_PORT}"
rpc_public_addr = "127.0.0.1:${GARAGE_RPC_PORT}"
rpc_secret = "${RPC_SECRET}"

[s3_api]
s3_region = "${GARAGE_REGION}"
api_bind_addr = "${GARAGE_BIND_ADDR}:${GARAGE_S3_PORT}"
root_domain = ".s3.garage"

[admin]
api_bind_addr = "${GARAGE_BIND_ADDR}:${GARAGE_ADMIN_PORT}"
admin_token = "${ADMIN_TOKEN}"
EOF
chmod 600 "$CONFIG_FILE"

# ---------------------------------------------------------------------------
# 5. garagectl — start/stop/status/logs helper (replaces systemd)
# ---------------------------------------------------------------------------
log "Writing ${CTL}"
cat > "$CTL" <<EOF
#!/usr/bin/env bash
# garagectl — manage the rootless Garage instance. Managed by install-garage.sh
set -u
BIN="${GARAGE_BIN}"
CFG="${CONFIG_FILE}"
LOG="${LOG_FILE}"
PID="${PID_FILE}"

# Bootstrap credentials consumed on first start by
# --single-node --default-access-key --default-bucket
export GARAGE_DEFAULT_ACCESS_KEY="${GARAGE_ACCESS_KEY}"
export GARAGE_DEFAULT_SECRET_KEY="${GARAGE_SECRET_KEY}"
export GARAGE_DEFAULT_BUCKET="${GARAGE_BUCKET}"

running() { [[ -f "\$PID" ]] && kill -0 "\$(cat "\$PID")" 2>/dev/null; }

case "\${1:-status}" in
  start)
    if running; then echo "garage already running (pid \$(cat "\$PID"))"; exit 0; fi
    nohup "\$BIN" -c "\$CFG" server --single-node \\
        --default-access-key --default-bucket >> "\$LOG" 2>&1 &
    echo \$! > "\$PID"
    echo "garage started (pid \$(cat "\$PID"))"
    ;;
  stop)
    if running; then
      kill "\$(cat "\$PID")" && rm -f "\$PID" && echo "garage stopped"
    else
      echo "garage not running"; rm -f "\$PID"
    fi
    ;;
  restart) "\$0" stop; sleep 2; "\$0" start ;;
  status)
    if running; then echo "garage running (pid \$(cat "\$PID"))"; else echo "garage not running"; exit 1; fi
    ;;
  logs) tail -f "\$LOG" ;;
  cli)  shift; exec "\$BIN" -c "\$CFG" "\$@" ;;
  *) echo "usage: garagectl {start|stop|restart|status|logs|cli <args>}"; exit 2 ;;
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
# 6. Start
# ---------------------------------------------------------------------------
log "Starting Garage"
"$CTL" start

for _ in {1..30}; do
  if curl -fsS "http://127.0.0.1:${GARAGE_ADMIN_PORT}/health" >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 1
done
[[ "${READY:-0}" == "1" ]] || {
  tail -n 40 "$LOG_FILE"
  die "Garage did not become healthy — see the log above"
}

GCLI=("$GARAGE_BIN" -c "$CONFIG_FILE")

# ---------------------------------------------------------------------------
# 7. Verify bootstrap + grant bucket-creation rights (MinIO-root-like key)
# ---------------------------------------------------------------------------
log "Cluster status"
"${GCLI[@]}" status || warn "garage status failed (non-fatal)"

if "${GCLI[@]}" key list 2>/dev/null | grep -q "$GARAGE_ACCESS_KEY"; then
  log "Access key '${GARAGE_ACCESS_KEY}' present"
else
  warn "Access key not found — check: ${CTL} logs"
fi
if "${GCLI[@]}" bucket list 2>/dev/null | grep -q "$GARAGE_BUCKET"; then
  log "Bucket '${GARAGE_BUCKET}' present"
else
  warn "Default bucket not found — check: ${CTL} logs"
fi

log "Allowing '${GARAGE_ACCESS_KEY}' to create additional buckets"
"${GCLI[@]}" key allow --create-bucket "$GARAGE_ACCESS_KEY" >/dev/null 2>&1 \
  || warn "Could not grant create-bucket (run manually: ${CTL} cli key allow --create-bucket ${GARAGE_ACCESS_KEY})"

# ---------------------------------------------------------------------------
# 8. Synthetic data generation -> Garage
# ---------------------------------------------------------------------------
# Runs the V2 generators with --s3. Their built-in defaults already match this
# installer (endpoint :9000, region garage, bucket datafederation, creds
# above), so no extra wiring is needed — garage_s3.py next to the generators
# does the upload. Local copies of every artifact are kept in ${GEN_OUT_DIR}.
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

  log "Generating HR roster (${GEN_DIR}/gen_hr_csv.py)"
  python3 "${GEN_DIR}/gen_hr_csv.py" --parquet hr_roster.parquet --s3 \
    || die "gen_hr_csv.py failed"

  log "Generating transaction archive (${TXN_ROWS} rows — this takes a while)"
  python3 "${GEN_DIR}/gen_parquet.py" --rows "$TXN_ROWS" --s3 \
    || die "gen_parquet.py failed"

  log "Generating application logs (${LOG_ROWS} rows)"
  python3 "${GEN_DIR}/gen_parquet_logs.py" --rows "$LOG_ROWS" --s3 \
    || die "gen_parquet_logs.py failed"

  log "Generating order documents (${ORDER_ROWS} rows, NDJSON)"
  python3 "${GEN_DIR}/gen_parquet_orders.py" --rows "$ORDER_ROWS" --ndjson-only --s3 \
    || die "gen_parquet_orders.py failed"

  cd - >/dev/null
  DATAGEN_DONE=1
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF
────────────────────────────────────────────────────────────
 Garage is running (rootless, as $(whoami))
────────────────────────────────────────────────────────────
 S3 API       : http://${IP:-<host>}:${GARAGE_S3_PORT}   (path-style, region: ${GARAGE_REGION})
 Admin API    : http://${IP:-<host>}:${GARAGE_ADMIN_PORT} (Bearer token below)
 Access key   : ${GARAGE_ACCESS_KEY}
 Secret key   : ${GARAGE_SECRET_KEY}
 Admin token  : ${ADMIN_TOKEN}
 Bucket       : ${GARAGE_BUCKET}
 Meta dir     : ${GARAGE_META_DIR}
 Data dir     : ${GARAGE_DATA_DIR}
 Service      : ${CTL} {start|stop|restart|status}
 Logs         : ${CTL} logs
 Admin CLI    : ${CTL} cli status   (also: key list, bucket list, ...)
 Data         : $(if [[ "${DATAGEN_DONE:-0}" == "1" ]]; then
                   echo "generated -> s3://${GARAGE_BUCKET}/{hr,transactions,logs,orders}/ (local: ${GEN_OUT_DIR})"
                 else
                   echo "not generated (see warnings above)"
                 fi)

 NOTE: no root was used. Firewall/security-group ports ${GARAGE_S3_PORT} and
 ${GARAGE_ADMIN_PORT} must already be reachable if remote access is needed.

 aws-cli example:
   export AWS_ACCESS_KEY_ID='${GARAGE_ACCESS_KEY}'
   export AWS_SECRET_ACCESS_KEY='${GARAGE_SECRET_KEY}'
   aws --endpoint-url http://127.0.0.1:${GARAGE_S3_PORT} --region ${GARAGE_REGION} s3 ls
────────────────────────────────────────────────────────────
EOF
