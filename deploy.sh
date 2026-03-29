#!/bin/bash
set -e

ROUTER_HOST="192.168.1.1"
ROUTER_PORT=222
ROUTER_USER="root"
ROUTER_PASS="keenetic"
BINARY_NAME="reroute"
TARGET="mipsel-unknown-linux-musl"
REMOTE_BIN="/opt/bin/${BINARY_NAME}"
SERVICE="/opt/etc/init.d/S99reroute"
HTTP_PORT=8888

echo "==> Building for ${TARGET}..."
docker run --rm -v "$(pwd)":/app -w /app \
  messense/rust-musl-cross:mipsel-musl \
  cargo build --release --target "${TARGET}"

RELEASE_DIR="target/${TARGET}/release"

echo "==> Starting HTTP server on port ${HTTP_PORT}..."
# Start a simple HTTP server in the background
python3 -m http.server "${HTTP_PORT}" --directory "${RELEASE_DIR}" &
HTTP_PID=$!
trap "kill ${HTTP_PID} 2>/dev/null" EXIT

# Get local IP for the router to download from
LOCAL_IP=$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
DOWNLOAD_URL="http://${LOCAL_IP}:${HTTP_PORT}/${BINARY_NAME}"

echo "==> Deploying to router ${ROUTER_HOST}:${ROUTER_PORT}..."
echo "==> Download URL: ${DOWNLOAD_URL}"

sshpass -p "${ROUTER_PASS}" ssh -o StrictHostKeyChecking=no -p "${ROUTER_PORT}" "${ROUTER_USER}@${ROUTER_HOST}" sh -s <<EOF
  echo "Stopping service..."
  ${SERVICE} stop || true
  sleep 1

  echo "Downloading new binary..."
  wget -O ${REMOTE_BIN} ${DOWNLOAD_URL}

  echo "Setting permissions..."
  chmod +x ${REMOTE_BIN}

  echo "Starting service..."
  ${SERVICE} start

  echo "Done! Watching logs for 10 seconds..."
  tail -f /opt/var/log/reroute.log &
  TAIL_PID=\$!
  sleep 10
  kill \$TAIL_PID 2>/dev/null
EOF

echo "==> Deploy complete!"
