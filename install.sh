#!/bin/sh
set -e

REPO="Leonqn/reroute"
INSTALL_DIR="/opt/bin"
CONFIG_DIR="/opt/etc/reroute"
DATA_DIR="/opt/var/reroute"
LOG_DIR="/opt/var/log"
INIT_DIR="/opt/etc/init.d"
LOGROTATE_DIR="/opt/etc/logrotate.d"
BINARY_NAME="reroute"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Reroute installer for Keenetic (Entware) ==="

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    mips)
        # Check endianness
        if echo -n I | od -t o2 | head -1 | grep -q '000001'; then
            TARGET="mipsel-unknown-linux-musl"
        else
            TARGET="mips-unknown-linux-musl"
        fi
        ;;
    mipsel)
        TARGET="mipsel-unknown-linux-musl"
        ;;
    aarch64)
        TARGET="aarch64-unknown-linux-musl"
        ;;
    armv7*)
        TARGET="armv7-unknown-linux-musleabihf"
        ;;
    *)
        echo "Error: unsupported architecture: $ARCH"
        echo "Supported: mips, mipsel, aarch64, armv7"
        exit 1
        ;;
esac

ASSET_NAME="${BINARY_NAME}-${TARGET}"
echo "Detected architecture: $ARCH -> $TARGET"

# Install dependencies
echo "Installing dependencies..."
opkg update
opkg install curl ca-certificates ca-bundle logrotate cron

# Get latest release tag
echo "Fetching latest release..."
LATEST_TAG=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "Error: failed to get latest release"
    exit 1
fi

echo "Latest release: $LATEST_TAG"

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${ASSET_NAME}"

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$INIT_DIR" "$LOGROTATE_DIR" /opt/var/spool/cron/crontabs

# Download binary
echo "Downloading $ASSET_NAME..."
curl -L -o "${INSTALL_DIR}/${BINARY_NAME}" "$DOWNLOAD_URL"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
echo "Binary installed to ${INSTALL_DIR}/${BINARY_NAME}"

# Copy config
if [ -f "${SCRIPT_DIR}/config.yml" ]; then
    cp "${SCRIPT_DIR}/config.yml" "${CONFIG_DIR}/config.yml"
    echo "Config copied to ${CONFIG_DIR}/config.yml"
elif [ -f "${CONFIG_DIR}/config.yml" ]; then
    echo "Config already exists at ${CONFIG_DIR}/config.yml, skipping"
else
    echo "WARNING: config.yml not found next to this script and no existing config."
    echo "Place your config.yml at ${CONFIG_DIR}/config.yml before starting."
fi

# Create init script
cat > "${INIT_DIR}/S99reroute" << 'INITEOF'
#!/bin/sh

ENABLED=yes
PROCS=reroute
DESC=$PROCS

start() {
    echo "Starting $DESC..."
    RUST_LOG=info /opt/bin/$PROCS /opt/etc/reroute/config.yml \
        >> /opt/var/log/reroute.log 2>&1 &
}

stop() {
    echo "Stopping $DESC..."
    killall $PROCS 2>/dev/null
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; sleep 1; start ;;
    *) echo "Usage: $0 {start|stop|restart}" ;;
esac
INITEOF
chmod +x "${INIT_DIR}/S99reroute"
echo "Init script created"

# Create logrotate config
cat > "${LOGROTATE_DIR}/reroute" << 'LREOF'
/opt/var/log/reroute.log {
    size 1M
    rotate 2
    compress
    missingok
    copytruncate
}
LREOF
echo "Logrotate config created"

# Setup crontab for logrotate
CRON_LINE="0 * * * * /opt/sbin/logrotate /opt/etc/logrotate.conf"
if ! crontab -l 2>/dev/null | grep -qF "logrotate"; then
    # crontab may not exist yet on a fresh Entware install
    (crontab -l 2>/dev/null || true; echo "$CRON_LINE") | crontab -
    echo "Crontab entry added for logrotate"
else
    echo "Logrotate crontab entry already exists, skipping"
fi

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit config if needed: vi ${CONFIG_DIR}/config.yml"
echo "  2. Disable built-in DNS (via Keenetic CLI):"
echo "       opkg dns-override"
echo "       system configuration save"
echo "  3. Start the service:"
echo "       ${INIT_DIR}/S99reroute start"
echo "  4. Check logs:"
echo "       tail -f ${LOG_DIR}/reroute.log"
