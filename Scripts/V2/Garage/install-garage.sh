#!/usr/bin/env bash
#
# install-garage.sh — Single-node Garage installer for Ubuntu (20.04 / 22.04 / 24.04)
#
# Installs the Garage server, creates a dedicated service account, writes a
# systemd unit, and exposes the S3 API on all interfaces. Uses Garage's
# --single-node bootstrap (v2.3.0+) to auto-create the cluster layout plus a
# default access key and bucket, so it behaves like a drop-in MinIO stand-in.
#
# Usage: sudo ./install-garage.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GARAGE_ACCESS_KEY="minioadmin"                  # kept for MinIO drop-in compat
GARAGE_SECRET_KEY='datafederation_hooray!'
GARAGE_BUCKET="datafederation"                  # default bucket created at boot

GARAGE_META_DIR="/var/lib/garage/meta"          # metadata (small, fast disk)
GARAGE_DATA_DIR="/mnt/garage/data"              # object storage volume
GARAGE_S3_PORT="9000"                           # S3 API endpoint (same as MinIO)
GARAGE_RPC_PORT="3901"                          # inter-node RPC (loopback only)
GARAGE_ADMIN_PORT="3903"                        # admin API + metrics
GARAGE_BIND_ADDR="0.0.0.0"                      # S3/admin listen on all interfaces
GARAGE_SERVICE_USER="garage-user"
GARAGE_REGION="garage"                          # S3 region name clients must use

# Release to install. Pin a tag from https://garagehq.deuxfleurs.fr/download/
GARAGE_VERSION="v2.3.0"                         # requires >= v2.3.0 for --single-node

GARAGE_BIN="/usr/local/bin/garage"
CONFIG_FILE="/etc/garage.toml"
ENV_FILE="/etc/default/garage"
UNIT_FILE="/etc/systemd/system/garage.service"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run this script as root (sudo $0)"

# ---------------------------------------------------------------------------
# 1. Dependencies
# ---------------------------------------------------------------------------
log "Installing prerequisites"
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
APT_OPTS=(-o DPkg::Lock::Timeout=120 -o Acquire::ForceIPv4=true
          -o Acquire::http::Timeout=15 -o Acquire::Retries=3)
apt-get "${APT_OPTS[@]}" install -y curl ca-certificates openssl

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
log "Downloading Garage server (${GARAGE_VERSION})"
systemctl stop garage 2>/dev/null || true
curl -fsSL --retry 3 -o "${GARAGE_BIN}.tmp" "$GARAGE_URL" \
  || die "Download failed: $GARAGE_URL"
chmod 755 "${GARAGE_BIN}.tmp"
mv -f "${GARAGE_BIN}.tmp" "$GARAGE_BIN"
"$GARAGE_BIN" --version | head -n1

# ---------------------------------------------------------------------------
# 4. Service account + directories
# ---------------------------------------------------------------------------
if ! getent group "$GARAGE_SERVICE_USER" >/dev/null; then
  groupadd -r "$GARAGE_SERVICE_USER"
fi
if ! id -u "$GARAGE_SERVICE_USER" >/dev/null 2>&1; then
  useradd -M -r -g "$GARAGE_SERVICE_USER" -s /sbin/nologin "$GARAGE_SERVICE_USER"
  log "Created service account: ${GARAGE_SERVICE_USER}"
fi

log "Preparing directories: ${GARAGE_META_DIR} and ${GARAGE_DATA_DIR}"
mkdir -p "$GARAGE_META_DIR" "$GARAGE_DATA_DIR"
chown -R "${GARAGE_SERVICE_USER}:${GARAGE_SERVICE_USER}" \
  "$(dirname "$GARAGE_META_DIR")" "$GARAGE_DATA_DIR"
chmod 750 "$GARAGE_DATA_DIR"

# ---------------------------------------------------------------------------
# 5. Configuration + environment file
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
chown root:"$GARAGE_SERVICE_USER" "$CONFIG_FILE"
chmod 640 "$CONFIG_FILE"

log "Writing ${ENV_FILE}"
cat > "$ENV_FILE" <<EOF
# Garage bootstrap credentials — managed by install-garage.sh
# Consumed by 'garage server --single-node --default-access-key --default-bucket'
GARAGE_DEFAULT_ACCESS_KEY="${GARAGE_ACCESS_KEY}"
GARAGE_DEFAULT_SECRET_KEY="${GARAGE_SECRET_KEY}"
GARAGE_DEFAULT_BUCKET="${GARAGE_BUCKET}"
EOF
chown root:"$GARAGE_SERVICE_USER" "$ENV_FILE"
chmod 640 "$ENV_FILE"

# ---------------------------------------------------------------------------
# 6. systemd unit
# ---------------------------------------------------------------------------
log "Writing ${UNIT_FILE}"
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Garage Object Storage
Documentation=https://garagehq.deuxfleurs.fr/documentation/
Wants=network-online.target
After=network-online.target
AssertFileIsExecutable=${GARAGE_BIN}

[Service]
Type=simple
User=${GARAGE_SERVICE_USER}
Group=${GARAGE_SERVICE_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=${GARAGE_BIN} -c ${CONFIG_FILE} server --single-node --default-access-key --default-bucket
Restart=always
RestartSec=5s
LimitNOFILE=1048576
TasksMax=infinity
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# 7. Firewall (only if ufw is active)
# ---------------------------------------------------------------------------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  log "Opening ports ${GARAGE_S3_PORT} and ${GARAGE_ADMIN_PORT} in ufw"
  ufw allow "${GARAGE_S3_PORT}/tcp" >/dev/null
  ufw allow "${GARAGE_ADMIN_PORT}/tcp" >/dev/null
else
  warn "ufw not active — skipping firewall rules (check any cloud security groups)"
fi

# ---------------------------------------------------------------------------
# 8. Start
# ---------------------------------------------------------------------------
log "Starting Garage"
systemctl daemon-reload
systemctl enable --now garage >/dev/null

for _ in {1..30}; do
  if curl -fsS "http://127.0.0.1:${GARAGE_ADMIN_PORT}/health" >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 1
done
[[ "${READY:-0}" == "1" ]] || {
  journalctl -u garage -n 40 --no-pager
  die "Garage did not become healthy — see the log above"
}

# ---------------------------------------------------------------------------
# 9. Verify bootstrap + grant bucket-creation rights (MinIO-root-like key)
# ---------------------------------------------------------------------------
GCLI=("$GARAGE_BIN" -c "$CONFIG_FILE")

log "Cluster status"
"${GCLI[@]}" status || warn "garage status failed (non-fatal)"

if "${GCLI[@]}" key list 2>/dev/null | grep -q "$GARAGE_ACCESS_KEY"; then
  log "Access key '${GARAGE_ACCESS_KEY}' present"
else
  warn "Access key not found — check: journalctl -u garage"
fi
if "${GCLI[@]}" bucket list 2>/dev/null | grep -q "$GARAGE_BUCKET"; then
  log "Bucket '${GARAGE_BUCKET}' present"
else
  warn "Default bucket not found — check: journalctl -u garage"
fi

log "Allowing '${GARAGE_ACCESS_KEY}' to create additional buckets"
"${GCLI[@]}" key allow --create-bucket "$GARAGE_ACCESS_KEY" >/dev/null 2>&1 \
  || warn "Could not grant create-bucket (run manually: garage key allow --create-bucket ${GARAGE_ACCESS_KEY})"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF
────────────────────────────────────────────────────────────
 Garage is running
────────────────────────────────────────────────────────────
 S3 API       : http://${IP:-<host>}:${GARAGE_S3_PORT}   (path-style, region: ${GARAGE_REGION})
 Admin API    : http://${IP:-<host>}:${GARAGE_ADMIN_PORT} (Bearer token below)
 Access key   : ${GARAGE_ACCESS_KEY}
 Secret key   : ${GARAGE_SECRET_KEY}
 Admin token  : ${ADMIN_TOKEN}
 Bucket       : ${GARAGE_BUCKET}
 Meta dir     : ${GARAGE_META_DIR}
 Data dir     : ${GARAGE_DATA_DIR}
 Service      : systemctl status garage
 Logs         : journalctl -u garage -f
 Admin CLI    : garage -c ${CONFIG_FILE} status | key list | bucket list

 aws-cli example:
   export AWS_ACCESS_KEY_ID='${GARAGE_ACCESS_KEY}'
   export AWS_SECRET_ACCESS_KEY='${GARAGE_SECRET_KEY}'
   aws --endpoint-url http://127.0.0.1:${GARAGE_S3_PORT} --region ${GARAGE_REGION} s3 ls
────────────────────────────────────────────────────────────
EOF
