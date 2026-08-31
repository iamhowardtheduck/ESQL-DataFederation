#!/usr/bin/env bash
#
# install-garage.sh — Single-node Garage installer for the workshop host.
#
# PROVISIONING STEP ONLY. Installs and starts Garage; generates NO data.
# Data generation is done later, by the workshop user, with seed-garage.sh.
#
# Root-aware: this script is normally run once, as root, from the host setup
# script — but it installs Garage *for* the workshop user (GARAGE_USER,
# default "elastic") so that afterwards everything is owned by that user and
# the server can be stopped/restarted without root:
#
#   /usr/local/bin/garage            server binary (~/.local/bin/garage if not root)
#   <BASE_DIR>/garage.toml           configuration        (default ~elastic/garage)
#   <BASE_DIR>/meta                  metadata
#   <DATA_DIR>                       object data          (default /mnt/garage/data)
#   <BASE_DIR>/garagectl             start/stop/restart/status/logs/cli helper
#   <BASE_DIR>/garage.log            server log
#   <BASE_DIR>/install-summary.txt   endpoint, keys, admin token
#
# The server process is started AS THE WORKSHOP USER (via runuser when this
# script is root) and a @reboot entry is added to that user's crontab.
# Ports 9000/3901/3903 are unprivileged. No systemd, no /etc, no ufw.
#
# If run as a non-root user (or GARAGE_USER does not exist), it falls back to
# a plain rootless install under the invoking user's home.
#
# Usage (as root, at provisioning):   bash install-garage.sh
# Env overrides: GARAGE_USER, GARAGE_HOME, GARAGE_DATA_DIR, GARAGE_VERSION
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GARAGE_ACCESS_KEY="minioadmin"                  # kept for MinIO drop-in compat
GARAGE_SECRET_KEY='datafederation_hooray!'
GARAGE_BUCKET="datafederation"                  # default bucket created at boot

GARAGE_S3_PORT="9000"                           # S3 API endpoint (same as MinIO)
GARAGE_RPC_PORT="3901"                          # inter-node RPC (loopback only)
GARAGE_ADMIN_PORT="3903"                        # admin API + metrics
GARAGE_BIND_ADDR="0.0.0.0"                      # S3/admin listen on all interfaces
GARAGE_REGION="garage"                          # S3 region name clients must use

# Release to install. Pin a tag from https://garagehq.deuxfleurs.fr/download/
GARAGE_VERSION="${GARAGE_VERSION:-v2.3.0}"      # requires >= v2.3.0 for --single-node

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. Who are we installing for?
# ---------------------------------------------------------------------------
GARAGE_USER="${GARAGE_USER:-elastic}"
AS_ROOT=0
if [[ $EUID -eq 0 && "$GARAGE_USER" != "root" ]] && getent passwd "$GARAGE_USER" >/dev/null; then
  AS_ROOT=1
  TARGET_HOME="$(getent passwd "$GARAGE_USER" | cut -d: -f6)"
  GARAGE_GROUP="$(id -gn "$GARAGE_USER")"
  command -v runuser >/dev/null || die "runuser not found (util-linux) — needed to start Garage as ${GARAGE_USER}"
  log "Running as root — installing Garage for user '${GARAGE_USER}' (${TARGET_HOME})"
else
  [[ $EUID -eq 0 ]] && warn "User '${GARAGE_USER}' not found — installing for root instead"
  GARAGE_USER="$(id -un)"
  GARAGE_GROUP="$(id -gn)"
  TARGET_HOME="$HOME"
  log "Rootless install for user '${GARAGE_USER}' (${TARGET_HOME})"
fi

BASE_DIR="${GARAGE_HOME:-${TARGET_HOME}/garage}"       # config, meta, log, helper
if [[ $AS_ROOT -eq 1 ]]; then
  GARAGE_DATA_DIR="${GARAGE_DATA_DIR:-/mnt/garage/data}"
  GARAGE_BIN="/usr/local/bin/garage"
else
  GARAGE_DATA_DIR="${GARAGE_DATA_DIR:-${BASE_DIR}/data}"
  GARAGE_BIN="${TARGET_HOME}/.local/bin/garage"
fi
GARAGE_META_DIR="${BASE_DIR}/meta"
CONFIG_FILE="${BASE_DIR}/garage.toml"
LOG_FILE="${BASE_DIR}/garage.log"
PID_FILE="${BASE_DIR}/garage.pid"
CTL="${BASE_DIR}/garagectl"
SUMMARY_FILE="${BASE_DIR}/install-summary.txt"

# run a command as the workshop user (no-op wrapper when not root)
as_user() {
  if [[ $AS_ROOT -eq 1 ]]; then runuser -u "$GARAGE_USER" -- "$@"; else "$@"; fi
}
# hand ownership of a path to the workshop user (no-op when not root)
own() {
  if [[ $AS_ROOT -eq 1 ]]; then chown -R "${GARAGE_USER}:${GARAGE_GROUP}" "$@"; fi
}

# ---------------------------------------------------------------------------
# 1. Dependency check
# ---------------------------------------------------------------------------
log "Checking prerequisites"
MISSING=()
for c in curl openssl; do
  command -v "$c" >/dev/null || MISSING+=("$c")
done
[[ ${#MISSING[@]} -eq 0 ]] || die "Missing required tools: ${MISSING[*]}"

# ---------------------------------------------------------------------------
# 2. Architecture detection
# ---------------------------------------------------------------------------
case "$(uname -m)" in
  x86_64)  TRIPLE="x86_64-unknown-linux-musl" ;;
  aarch64) TRIPLE="aarch64-unknown-linux-musl" ;;
  *) die "Unsupported architecture: $(uname -m)" ;;
esac
log "Detected architecture: ${TRIPLE}"
GARAGE_URL="https://garagehq.deuxfleurs.fr/_releases/${GARAGE_VERSION}/${TRIPLE}/garage"

# ---------------------------------------------------------------------------
# 3. Directories + binary
# ---------------------------------------------------------------------------
log "Creating ${BASE_DIR}, ${GARAGE_META_DIR}, ${GARAGE_DATA_DIR}"
mkdir -p "$(dirname "$GARAGE_BIN")" "$BASE_DIR" "$GARAGE_META_DIR" "$GARAGE_DATA_DIR"
own "$BASE_DIR" "$GARAGE_DATA_DIR"

# stop a previous instance before replacing the binary
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  log "Stopping running Garage instance"
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
  sleep 2
fi

log "Downloading Garage server (${GARAGE_VERSION}) -> ${GARAGE_BIN}"
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
# Garage configuration — managed by install-garage.sh
metadata_dir = "${GARAGE_META_DIR}"
data_dir     = "${GARAGE_DATA_DIR}"
replication_factor = 1

rpc_bind_addr   = "127.0.0.1:${GARAGE_RPC_PORT}"
rpc_public_addr = "127.0.0.1:${GARAGE_RPC_PORT}"
rpc_secret      = "${RPC_SECRET}"

[s3_api]
s3_region     = "${GARAGE_REGION}"
api_bind_addr = "${GARAGE_BIND_ADDR}:${GARAGE_S3_PORT}"
root_domain   = ".s3.garage"

[admin]
api_bind_addr = "${GARAGE_BIND_ADDR}:${GARAGE_ADMIN_PORT}"
admin_token   = "${ADMIN_TOKEN}"
EOF
chmod 600 "$CONFIG_FILE"
own "$CONFIG_FILE"

# ---------------------------------------------------------------------------
# 5. garagectl — start/stop/status/logs helper (replaces systemd)
# ---------------------------------------------------------------------------
log "Writing ${CTL}"
cat > "$CTL" <<EOF
#!/usr/bin/env bash
# garagectl — manage the Garage instance. Managed by install-garage.sh
# Run this as ${GARAGE_USER} (the user the server runs as).
set -u
BIN="${GARAGE_BIN}"
CFG="${CONFIG_FILE}"
LOG="${LOG_FILE}"
PID="${PID_FILE}"

# Bootstrap credentials consumed on first start by
#   --single-node --default-access-key --default-bucket
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
own "$CTL"

# survive reboots via the workshop user's crontab, when crontab is available
if command -v crontab >/dev/null; then
  CRON=(crontab); [[ $AS_ROOT -eq 1 ]] && CRON=(crontab -u "$GARAGE_USER")
  CRON_LINE="@reboot ${CTL} start"
  if ! "${CRON[@]}" -l 2>/dev/null | grep -Fq "$CRON_LINE"; then
    ( "${CRON[@]}" -l 2>/dev/null; echo "$CRON_LINE" ) | "${CRON[@]}" - 2>/dev/null \
      && log "Added @reboot crontab entry for ${GARAGE_USER}" \
      || warn "Could not modify crontab — restart manually after reboot: ${CTL} start"
  fi
else
  warn "crontab unavailable — restart manually after reboot: ${CTL} start"
fi

# ---------------------------------------------------------------------------
# 6. Start (as the workshop user)
# ---------------------------------------------------------------------------
log "Starting Garage as ${GARAGE_USER}"
as_user "$CTL" start

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

# ---------------------------------------------------------------------------
# 7. Verify bootstrap + grant bucket-creation rights (MinIO-root-like key)
# ---------------------------------------------------------------------------
GCLI=("$GARAGE_BIN" -c "$CONFIG_FILE")

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
# 8. Summary
# ---------------------------------------------------------------------------
HOSTN="$(hostname -s 2>/dev/null || hostname)"
ENDPOINT="http://${HOSTN}:${GARAGE_S3_PORT}"

cat > "$SUMMARY_FILE" <<EOF
Garage install — $(date -u +%Y-%m-%dT%H:%M:%SZ)   (runs as: ${GARAGE_USER})

S3 API      : ${ENDPOINT}   (path-style, region: ${GARAGE_REGION})
Admin API   : http://${HOSTN}:${GARAGE_ADMIN_PORT}   (Authorization: Bearer <token>)
Admin token : ${ADMIN_TOKEN}
Access key  : ${GARAGE_ACCESS_KEY}
Secret key  : ${GARAGE_SECRET_KEY}
Bucket      : ${GARAGE_BUCKET}
Meta dir    : ${GARAGE_META_DIR}
Data dir    : ${GARAGE_DATA_DIR}
Service     : ${CTL} {start|stop|restart|status|logs}
Admin CLI   : ${CTL} cli status | key list | bucket list
Seed data   : bash $(dirname "$0")/seed-garage.sh   (as ${GARAGE_USER})
EOF
chmod 600 "$SUMMARY_FILE"
own "$SUMMARY_FILE" "$BASE_DIR"

log "Garage ${GARAGE_VERSION} is up at ${ENDPOINT} (bucket: ${GARAGE_BUCKET}, empty)"
log "Details: ${SUMMARY_FILE}"
log "When the workshop begins, run seed-garage.sh as ${GARAGE_USER} to generate the datasets."
