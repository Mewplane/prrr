#!/bin/bash
# Install prrr VPN client as a systemd service
# Usage: sudo ./install-client.sh [config-file]
#
# After installation:
#   sudo systemctl start prrr-client   # Connect VPN
#   sudo systemctl stop prrr-client    # Disconnect VPN
#   systemctl status prrr-client       # Check status
#   journalctl -u prrr-client -f       # Follow logs

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_SRC="${1:-}"

# Find prrr binary. Prefer a fresh build from this repository: running this
# installer from the repo means "deploy what I just built". A bare
# `command -v prrr` under sudo resolves PATH via secure_path, which can pick
# up a stale copy and even collide with the install target (same file).
if [[ -x "$SCRIPT_DIR/../../target/release/prrr" ]]; then
    PRRR_BIN="$SCRIPT_DIR/../../target/release/prrr"
else
    PRRR_BIN="$(command -v prrr 2>/dev/null || echo "")"
fi

if [[ -z "$PRRR_BIN" ]]; then
    echo "Error: prrr binary not found. Build with 'cargo build --release' first." >&2
    exit 1
fi

echo "Installing prrr VPN client..."

# Install binary
install -m 755 "$PRRR_BIN" /usr/local/bin/prrr
echo "  Binary: /usr/local/bin/prrr"

# Install routing helper
install -m 755 "$SCRIPT_DIR/prrr-route" /usr/local/bin/prrr-route
echo "  Helper: /usr/local/bin/prrr-route"

# Install systemd service
install -m 644 "$SCRIPT_DIR/prrr-client.service" /etc/systemd/system/prrr-client.service
systemctl daemon-reload
echo "  Service: prrr-client.service"

# Keep NetworkManager away from the tunnel interface. An NM profile adopted for
# the TUN can be deactivated later and flush the tunnel address, which silently
# black-holes the tunnel (specs/bugs/BUG-network-manager-tun-address-loss.md).
if NM_CONF_FILE=$(bash "$SCRIPT_DIR/nm-unmanaged.sh"); then
    echo "  NetworkManager: ${NM_CONF_FILE}"
    if command -v nmcli &>/dev/null && systemctl is-active --quiet NetworkManager; then
        nmcli general reload CONFIG &>/dev/null || nmcli general reload &>/dev/null || true
    fi
fi

# Install config if provided
if [[ -n "$CONFIG_SRC" ]]; then
    mkdir -p /etc/prrr
    install -m 600 "$CONFIG_SRC" /etc/prrr/client.toml
    echo "  Config: /etc/prrr/client.toml"

    # Copy private key if referenced in config
    KEY_PATH=$(grep -E '^\s*private_key_path\s*=' "$CONFIG_SRC" 2>/dev/null | head -1 | sed 's/.*=\s*"\(.*\)"/\1/' || true)
    if [[ -n "$KEY_PATH" && -f "$KEY_PATH" ]]; then
        mkdir -p /etc/prrr/keys
        install -m 600 "$KEY_PATH" /etc/prrr/keys/client.key
        # Update config to point to new key location
        sed -i "s|$KEY_PATH|/etc/prrr/keys/client.key|" /etc/prrr/client.toml
        echo "  Key: /etc/prrr/keys/client.key"
    fi
fi

echo ""
echo "Installation complete! Usage:"
echo "  sudo systemctl start prrr-client    # Connect"
echo "  sudo systemctl stop prrr-client     # Disconnect"
echo "  systemctl status prrr-client        # Status"
echo "  journalctl -u prrr-client -f        # Logs"
echo ""
echo "To route ALL traffic through VPN, add to /etc/prrr/client.toml:"
echo '  [routing]'
echo '  all_traffic = true'
