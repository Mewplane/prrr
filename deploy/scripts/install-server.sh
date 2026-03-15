#!/usr/bin/env bash
#
# prrr Server Installation Script
# Supports: Ubuntu 22.04+, Debian 11+, Fedora 38+
#
# Usage:
#   curl -fsSL https://install.prrr.dev/server | sudo bash
#   or with options:
#   sudo bash install-server.sh --domain vpn.example.com --admin-pass MyPassword123

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
DOMAIN=""
ADMIN_PASSWORD=""
VPN_PORT="443"
ADMIN_PORT="9443"
INSTALL_CERTBOT=true
DATA_DIR="/var/lib/prrr"
CONFIG_DIR="/etc/prrr"
LOG_LEVEL="info"
MAX_CLIENTS="100"
TRANSPORT="masque"
DNS_SERVERS="1.1.1.1,8.8.8.8"

# Print functions
info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

fatal() {
    error "$*"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --admin-pass)
            ADMIN_PASSWORD="$2"
            shift 2
            ;;
        --vpn-port)
            VPN_PORT="$2"
            shift 2
            ;;
        --admin-port)
            ADMIN_PORT="$2"
            shift 2
            ;;
        --no-certbot)
            INSTALL_CERTBOT=false
            shift
            ;;
        --data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        --max-clients)
            MAX_CLIENTS="$2"
            shift 2
            ;;
        --transport)
            TRANSPORT="$2"
            shift 2
            ;;
        --dns)
            DNS_SERVERS="$2"
            shift 2
            ;;
        --certbot-email)
            CERTBOT_EMAIL="$2"
            shift 2
            ;;
        --help)
            echo "prrr Server Installation Script"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --domain DOMAIN          Domain name (required for Let's Encrypt)"
            echo "  --admin-pass PASSWORD    Admin panel password (required)"
            echo "  --vpn-port PORT          VPN port (default: 443)"
            echo "  --admin-port PORT        Admin panel HTTPS port (default: 9443)"
            echo "  --no-certbot             Skip Let's Encrypt certificate installation"
            echo "  --data-dir PATH          Data directory (default: /var/lib/prrr)"
            echo "  --max-clients N          Max concurrent clients (default: 100)"
            echo "  --transport TYPE         Transport: masque, harp, or both (default: masque)"
            echo "  --dns SERVERS            Comma-separated DNS servers (default: 1.1.1.1,8.8.8.8)"
            echo "  --certbot-email EMAIL    Email for Let's Encrypt notifications"
            echo "  --help                   Show this help message"
            exit 0
            ;;
        *)
            fatal "Unknown option: $1. Use --help for usage information."
            ;;
    esac
done

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   fatal "This script must be run as root"
fi

# Validate required parameters
if [[ -z "$ADMIN_PASSWORD" ]]; then
    fatal "Admin password is required. Use --admin-pass PASSWORD"
fi

if [[ "$INSTALL_CERTBOT" == true && -z "$DOMAIN" ]]; then
    fatal "Domain is required for Let's Encrypt. Use --domain your-domain.com or --no-certbot"
fi

# Validate transport
case "$TRANSPORT" in
    masque|harp|both) ;;
    *) fatal "Invalid transport: $TRANSPORT. Must be masque, harp, or both." ;;
esac

info "Starting prrr server installation..."
info "Domain: ${DOMAIN:-none}"
info "Transport: $TRANSPORT"
info "VPN Port: $VPN_PORT"
info "Admin Port: $ADMIN_PORT"
info "Let's Encrypt: $INSTALL_CERTBOT"

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
else
    fatal "Cannot detect OS. /etc/os-release not found."
fi

info "Detected OS: $OS $OS_VERSION"

# Install dependencies
info "Installing dependencies..."
case $OS in
    ubuntu|debian)
        apt-get update
        apt-get install -y curl wget git build-essential pkg-config libssl-dev argon2 nginx
        if [[ "$INSTALL_CERTBOT" == true ]]; then
            apt-get install -y certbot
        fi
        ;;
    fedora)
        dnf install -y curl wget git gcc pkg-config openssl-devel argon2 nginx
        if [[ "$INSTALL_CERTBOT" == true ]]; then
            dnf install -y certbot
        fi
        ;;
    *)
        fatal "Unsupported OS: $OS"
        ;;
esac

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    info "Rust already installed"
fi

# Check if prrr binary exists
if [[ ! -f /usr/local/bin/prrr ]]; then
    warn "prrr binary not found at /usr/local/bin/prrr"
    warn "Please build and install prrr manually:"
    warn "  cargo build --release --target x86_64-unknown-linux-musl"
    warn "  cp target/x86_64-unknown-linux-musl/release/prrr /usr/local/bin/"
    fatal "prrr binary is required to continue"
fi

info "prrr binary found: $(prrr --version 2>/dev/null || echo 'version unknown')"

# Create directories
info "Creating directories..."
mkdir -p "$CONFIG_DIR/keys"
mkdir -p "$DATA_DIR"

# Get Let's Encrypt certificates
if [[ "$INSTALL_CERTBOT" == true ]]; then
    info "Obtaining Let's Encrypt certificates for $DOMAIN..."

    # Temporarily stop nginx/prrr if running
    systemctl stop nginx 2>/dev/null || true
    systemctl stop prrr 2>/dev/null || true

    # Get certificate
    certbot certonly --standalone \
        -d "$DOMAIN" \
        -d "admin.$DOMAIN" \
        --non-interactive \
        --agree-tos \
        -m "admin@$DOMAIN" || fatal "Failed to obtain Let's Encrypt certificate"

    CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

    info "Certificates obtained successfully"

    # Install certbot renewal hook to restart prrr on cert renewal
    info "Installing certbot renewal hook for prrr..."
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/reload-prrr.sh << 'HOOK'
#!/bin/bash
systemctl restart prrr
HOOK
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-prrr.sh
else
    warn "Skipping Let's Encrypt setup"
    CERT_PATH="$CONFIG_DIR/cert.pem"
    KEY_PATH="$CONFIG_DIR/key.pem"

    if [[ ! -f "$CERT_PATH" ]]; then
        warn "No certificate found. Generating self-signed certificate..."
        warn "Self-signed certificates are detectable by DPI systems."
        warn "Clients must use --insecure flag to connect."
        openssl req -x509 -newkey rsa:4096 -keyout "$KEY_PATH" -out "$CERT_PATH" \
            -days 365 -nodes -subj "/CN=localhost"
    fi
fi

# Generate argon2 password hash
info "Generating password hash..."
PASSWORD_HASH=$(echo -n "$ADMIN_PASSWORD" | argon2 $(openssl rand -base64 16) -id -t 3 -m 16 -p 1 -l 32 -e)

# Generate PSK for probe resistance
info "Generating pre-shared key..."
PSK=$(head -c 32 /dev/urandom | base64)
echo "$PSK" > "$CONFIG_DIR/keys/psk.key"
chmod 600 "$CONFIG_DIR/keys/psk.key"

# Build DNS array for TOML
IFS=',' read -ra DNS_ARRAY <<< "$DNS_SERVERS"
DNS_TOML=""
for dns in "${DNS_ARRAY[@]}"; do
    DNS_TOML="${DNS_TOML}\"${dns}\", "
done
DNS_TOML="[${DNS_TOML%, }]"

# Build transport sections
TRANSPORTS=""
if [[ "$TRANSPORT" == "masque" || "$TRANSPORT" == "both" ]]; then
    TRANSPORTS+="
[[transports]]
name = \"masque\"
enabled = true
tls_cert = \"$CERT_PATH\"
tls_key = \"$KEY_PATH\"
max_idle_timeout = 300
keep_alive = 25
"
fi

if [[ "$TRANSPORT" == "harp" || "$TRANSPORT" == "both" ]]; then
    TRANSPORTS+="
[[transports]]
name = \"harp\"
enabled = true
tls_cert = \"$CERT_PATH\"
tls_key = \"$KEY_PATH\"
websocket_enabled = true
polling_enabled = true
h2_streaming_enabled = true
session_idle_timeout = 300
"
fi

# Create server configuration
info "Creating server configuration..."
cat > "$CONFIG_DIR/server.toml" << EOF
[server]
listen_address = "0.0.0.0:$VPN_PORT"
server_name = "$DOMAIN"
max_clients = $MAX_CLIENTS

[network]
subnet = "10.66.66.0/24"
dns_servers = $DNS_TOML
mtu = 1280
$TRANSPORTS
[keys]
identity_key_path = "$CONFIG_DIR/keys/server_identity.key"
pq_key_path = "$CONFIG_DIR/keys/server_pq.key"
psk_path = "$CONFIG_DIR/keys/psk.key"

[database]
path = "$DATA_DIR/clients.db"

[web_admin]
enabled = true
listen_addr = "0.0.0.0:8443"
admin_password_hash = "$PASSWORD_HASH"

[obfuscation]
enabled = true
tls_profile = "chrome"
padding_strategy = "http-sizes"
timing_jitter_ms = 50

[obfuscation.probe_resist]
enabled = true
psk = "$PSK"
tokens_per_second = 20
burst_capacity = 5

[logging]
level = "$LOG_LEVEL"
EOF

# Configure nginx as HTTPS reverse proxy for admin panel
info "Configuring nginx..."
cat > /etc/nginx/sites-available/prrr-admin << EOF
server {
    listen $ADMIN_PORT ssl http2;
    server_name admin.$DOMAIN;

    ssl_certificate $CERT_PATH;
    ssl_certificate_key $KEY_PATH;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

ln -sf /etc/nginx/sites-available/prrr-admin /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Enable IP forwarding and NAT for VPN traffic
info "Configuring IP forwarding and NAT..."
echo 1 > /proc/sys/net/ipv4/ip_forward
cat > /etc/sysctl.d/99-prrr.conf << SYSCTL
net.ipv4.ip_forward = 1
SYSCTL
sysctl -p /etc/sysctl.d/99-prrr.conf

MAIN_IFACE=$(ip route show default | awk '{print $5}' | head -1)
if command -v nft &> /dev/null; then
    nft add table nat 2>/dev/null || true
    nft add chain nat postrouting '{ type nat hook postrouting priority 100 ; }' 2>/dev/null || true
    nft add rule nat postrouting oifname "$MAIN_IFACE" masquerade 2>/dev/null || true
    nft list ruleset > /etc/nftables.conf
    systemctl enable nftables 2>/dev/null || true
elif command -v iptables &> /dev/null; then
    iptables -t nat -A POSTROUTING -o "$MAIN_IFACE" -j MASQUERADE
fi

# Test nginx configuration
nginx -t || fatal "nginx configuration test failed"

# Create systemd service
info "Creating systemd service..."
cat > /etc/systemd/system/prrr.service << EOF
[Unit]
Description=prrr VPN Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/prrr server --config $CONFIG_DIR/server.toml
Restart=on-failure
RestartSec=5s
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start services
info "Enabling and starting services..."
systemctl daemon-reload
systemctl enable prrr
systemctl start prrr
systemctl enable nginx
systemctl restart nginx

# Configure firewall
info "Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw allow 22/tcp comment "SSH"
    ufw allow 80/tcp comment "Let's Encrypt"
    ufw allow "$ADMIN_PORT/tcp" comment "prrr Admin Panel"
    if [[ "$TRANSPORT" == "masque" || "$TRANSPORT" == "both" ]]; then
        ufw allow "$VPN_PORT/udp" comment "prrr MASQUE"
    fi
    if [[ "$TRANSPORT" == "harp" || "$TRANSPORT" == "both" ]]; then
        ufw allow "$VPN_PORT/tcp" comment "prrr HARP"
    fi
elif command -v firewall-cmd &> /dev/null; then
    if [[ "$TRANSPORT" == "masque" || "$TRANSPORT" == "both" ]]; then
        firewall-cmd --permanent --add-port="$VPN_PORT/udp"
    fi
    if [[ "$TRANSPORT" == "harp" || "$TRANSPORT" == "both" ]]; then
        firewall-cmd --permanent --add-port="$VPN_PORT/tcp"
    fi
    firewall-cmd --permanent --add-port="$ADMIN_PORT/tcp"
    firewall-cmd --permanent --add-port=80/tcp
    firewall-cmd --reload
fi

# Wait for services to start
sleep 3

# Check service status
if systemctl is-active --quiet prrr; then
    info "✓ prrr server is running"
else
    error "✗ prrr server failed to start"
    journalctl -u prrr -n 20 --no-pager
    exit 1
fi

if systemctl is-active --quiet nginx; then
    info "✓ nginx is running"
else
    error "✗ nginx failed to start"
    journalctl -u nginx -n 20 --no-pager
    exit 1
fi

# Print success message
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  prrr Server Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Server Details:"
echo "  VPN Transport:   $TRANSPORT"
if [[ "$TRANSPORT" == "masque" || "$TRANSPORT" == "both" ]]; then
    echo "  MASQUE Endpoint: ${DOMAIN:-$SERVER_IP}:$VPN_PORT (UDP/QUIC)"
fi
if [[ "$TRANSPORT" == "harp" || "$TRANSPORT" == "both" ]]; then
    echo "  HARP Endpoint:   ${DOMAIN:-$SERVER_IP}:$VPN_PORT (TCP/HTTPS)"
fi
echo "  Admin Panel:     https://admin.$DOMAIN:$ADMIN_PORT"
echo "  Admin Username:  admin"
echo "  Admin Password:  $ADMIN_PASSWORD"
echo ""
echo "Next Steps:"
echo "  1. Open https://admin.$DOMAIN:$ADMIN_PORT in your browser"
echo "  2. Log in with the credentials above"
echo "  3. Add your first client"
echo ""
echo "Certificate Renewal:"
if [[ "$INSTALL_CERTBOT" == true ]]; then
    echo "  Automatic renewal is configured via systemd timer"
    echo "  Check status: systemctl status certbot.timer"
else
    echo "  Using self-signed certificate (manual renewal required)"
fi
echo ""
echo "Logs:"
echo "  Server:   journalctl -u prrr -f"
echo "  Nginx:    journalctl -u nginx -f"
echo ""
