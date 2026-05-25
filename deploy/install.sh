#!/usr/bin/env bash
# Quick installer for the vigilo daemon on a Linux server.
# Run as root: curl -fsSL https://raw.githubusercontent.com/voltagebots/vigilo/main/deploy/install.sh | bash
set -euo pipefail

INSTALL_BIN=/usr/local/bin/vigilo
CONFIG_DIR=/etc/vigilo
DATA_DIR=/var/lib/vigilo
SERVICE_FILE=/etc/systemd/system/vigilo.service

echo "==> Building vigilo..."
if ! command -v go &>/dev/null; then
  echo "Go not found. Install Go 1.23+ first: https://go.dev/dl/"
  exit 1
fi
go build -o "$INSTALL_BIN" ./cmd/vigilo/
chmod +x "$INSTALL_BIN"

echo "==> Creating user and directories..."
id -u vigilo &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin vigilo
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chown vigilo:vigilo "$DATA_DIR"

echo "==> Installing config (skip if exists)..."
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
  cp config.example.yaml "$CONFIG_DIR/config.yaml"
  echo "    Edit $CONFIG_DIR/config.yaml before starting the service."
fi

echo "==> Installing systemd service..."
cp deploy/vigilo.service "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable vigilo

echo ""
echo "Done. Edit $CONFIG_DIR/config.yaml then run:"
echo "  systemctl start vigilo"
echo "  journalctl -u vigilo -f"
