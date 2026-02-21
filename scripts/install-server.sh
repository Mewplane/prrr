#!/usr/bin/env bash
# FRD: specs/frds/FRD-P011.md
# prrr VPN Server Installation Script
# SPEC.md §1.1 — Single-command bootstrap
#
# Usage:
#   curl -fsSL https://install.prrr.dev/server | sudo bash -s -- [OPTIONS]
#
# Options:
#   --admin-pass PASSWORD    Set web admin password (default: auto-generated)
#   --port PORT              Server listening port (default: 443)
#   --web-port PORT          Web UI port (default: 8443)
#   --domain DOMAIN          Domain name for TLS
#   --no-web                 Skip web UI installation
#   --dns DNS_SERVERS        Custom DNS servers (default: 1.1.1.1,8.8.8.8)
#   --max-clients N          Maximum concurrent clients (default: 100)
#   --data-dir PATH          Data directory (default: /var/lib/prrr)
#   --log-level LEVEL        Logging level (default: info)

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

readonly PRRR_VERSION="latest"
readonly PRRR_BINARY_NAME="prrr"
readonly PRRR_CONFIG_DIR="/etc/prrr"
readonly PRRR_KEYS_DIR="/etc/prrr/keys"
readonly PRRR_TLS_DIR="/etc/prrr/tls"
readonly PRRR_LOG_DIR="/var/log/prrr"
readonly PRRR_SERVICE_NAME="prrr"
readonly PRRR_SERVICE_FILE="/etc/systemd/system/prrr.service"
readonly PRRR_BINARY_PATH="/usr/local/bin/prrr"
readonly PRRR_DOWNLOAD_BASE="https://github.com/prrr-vpn/releases"
readonly PRRR_GIT_REPO="https://github.com/prrr-vpn/prrr"

readonly DEFAULT_PORT=443
readonly DEFAULT_WEB_PORT=8443
readonly DEFAULT_DNS="1.1.1.1,8.8.8.8"
readonly DEFAULT_MAX_CLIENTS=100
readonly DEFAULT_DATA_DIR="/var/lib/prrr"
readonly DEFAULT_LOG_LEVEL="info"
readonly DEFAULT_SUBNET="10.66.66.0/24"

readonly MIN_RAM_KB=1048576        # 1 GB in KB
readonly MIN_DISK_KB=10485760      # 10 GB in KB
readonly ADMIN_PASS_LENGTH=32

# ANSI color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log_info()  { echo -e "${GREEN}✓${NC} $1"; }
log_warn()  { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1" >&2; exit 1; }
log_step()  { echo -e "${BLUE}→${NC} $1"; }

# ---------------------------------------------------------------------------
# Default option values
# ---------------------------------------------------------------------------

ADMIN_PASS=""
PORT="${DEFAULT_PORT}"
WEB_PORT="${DEFAULT_WEB_PORT}"
DOMAIN=""
NO_WEB=false
DNS="${DEFAULT_DNS}"
MAX_CLIENTS="${DEFAULT_MAX_CLIENTS}"
DATA_DIR="${DEFAULT_DATA_DIR}"
LOG_LEVEL="${DEFAULT_LOG_LEVEL}"

# ---------------------------------------------------------------------------
# Parse CLI arguments (SPEC.md §1.1)
# ---------------------------------------------------------------------------

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --admin-pass)
                ADMIN_PASS="$2"
                shift 2
                ;;
            --port)
                PORT="$2"
                shift 2
                ;;
            --web-port)
                WEB_PORT="$2"
                shift 2
                ;;
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --no-web)
                NO_WEB=true
                shift
                ;;
            --dns)
                DNS="$2"
                shift 2
                ;;
            --max-clients)
                MAX_CLIENTS="$2"
                shift 2
                ;;
            --data-dir)
                DATA_DIR="$2"
                shift 2
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1. Use --help for usage."
                ;;
        esac
    done
}

usage() {
    cat <<'EOF'
prrr VPN Server Installation Script

Usage:
  sudo bash install-server.sh [OPTIONS]

Options:
  --admin-pass PASSWORD    Set web admin password (default: auto-generated)
  --port PORT              Server listening port (default: 443)
  --web-port PORT          Web UI port (default: 8443)
  --domain DOMAIN          Domain name for TLS
  --no-web                 Skip web UI installation
  --dns DNS_SERVERS        Custom DNS servers (default: 1.1.1.1,8.8.8.8)
  --max-clients N          Maximum concurrent clients (default: 100)
  --data-dir PATH          Data directory (default: /var/lib/prrr)
  --log-level LEVEL        Logging level (default: info)
  -h, --help               Show this help message
EOF
}

# ---------------------------------------------------------------------------
# Environment detection (SPEC.md §1.1.1)
# ---------------------------------------------------------------------------

detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot detect OS: /etc/os-release not found"
    fi

    # shellcheck source=/dev/null
    . /etc/os-release

    OS="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-0}"

    case "${OS}" in
        ubuntu)
            if [[ "$(echo "${OS_VERSION}" | cut -d. -f1)" -lt 22 ]]; then
                log_error "Ubuntu 22.04+ required, found ${OS_VERSION}"
            fi
            ;;
        debian)
            if [[ "${OS_VERSION}" -lt 11 ]]; then
                log_error "Debian 11+ required, found ${OS_VERSION}"
            fi
            ;;
        fedora)
            if [[ "${OS_VERSION}" -lt 38 ]]; then
                log_error "Fedora 38+ required, found ${OS_VERSION}"
            fi
            ;;
        *)
            log_error "Unsupported OS: ${OS}. Supported: Ubuntu 22.04+, Debian 11+, Fedora 38+"
            ;;
    esac

    log_info "Detected OS: ${OS} ${OS_VERSION}"
}

detect_arch() {
    ARCH=$(uname -m)

    case "${ARCH}" in
        x86_64|aarch64)
            log_info "Detected architecture: ${ARCH}"
            ;;
        *)
            log_error "Unsupported architecture: ${ARCH}. Supported: x86_64, aarch64"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

check_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
    fi
    log_info "Running as root"
}

check_port_available() {
    local port="$1"
    local protocol="$2"
    local description="$3"

    if ss -tulnp 2>/dev/null | grep -q ":${port} "; then
        log_warn "Port ${port}/${protocol} is already in use (${description})"
    else
        log_info "Port ${port}/${protocol} available (${description})"
    fi
}

check_system_requirements() {
    # RAM check (1 GB minimum)
    local total_ram_kb
    total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if [[ "${total_ram_kb}" -lt "${MIN_RAM_KB}" ]]; then
        log_warn "System has less than 1GB RAM ($(( total_ram_kb / 1024 ))MB). Minimum recommended: 1GB"
    else
        log_info "RAM: $(( total_ram_kb / 1024 ))MB (minimum: 1024MB)"
    fi

    # CPU check (1 core minimum)
    local cpu_count
    cpu_count=$(nproc 2>/dev/null || echo 1)
    log_info "CPU cores: ${cpu_count}"

    # Disk space check (10 GB minimum)
    local avail_kb
    avail_kb=$(df --output=avail / 2>/dev/null | tail -1 | tr -d ' ')
    if [[ "${avail_kb}" -lt "${MIN_DISK_KB}" ]]; then
        log_warn "Less than 10GB disk space available ($(( avail_kb / 1024 / 1024 ))GB)"
    else
        log_info "Disk space: $(( avail_kb / 1024 / 1024 ))GB available (minimum: 10GB)"
    fi
}

# ---------------------------------------------------------------------------
# Dependency installation (SPEC.md §1.1.2)
# ---------------------------------------------------------------------------

install_deps_apt() {
    log_step "Installing dependencies via apt..."
    apt-get update -qq
    apt-get install -y -qq \
        curl \
        build-essential \
        pkg-config \
        libssl-dev \
        ufw \
        > /dev/null 2>&1
    log_info "Dependencies installed (apt)"
}

install_deps_dnf() {
    log_step "Installing dependencies via dnf..."
    dnf install -y -q \
        curl \
        gcc \
        openssl-devel \
        firewalld \
        > /dev/null 2>&1
    log_info "Dependencies installed (dnf)"
}

install_deps() {
    case "${OS}" in
        ubuntu|debian)
            install_deps_apt
            ;;
        fedora)
            install_deps_dnf
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Binary installation (SPEC.md §1.1.4)
# ---------------------------------------------------------------------------

install_binary() {
    log_step "Installing prrr binary..."

    # Try pre-compiled binary first
    local download_url="${PRRR_DOWNLOAD_BASE}/${PRRR_VERSION}/${PRRR_BINARY_NAME}-${ARCH}"

    if curl -fsSL "${download_url}" -o "/tmp/${PRRR_BINARY_NAME}" 2>/dev/null; then
        install -m 755 "/tmp/${PRRR_BINARY_NAME}" "${PRRR_BINARY_PATH}"
        rm -f "/tmp/${PRRR_BINARY_NAME}"
        log_info "Binary installed from pre-compiled release: ${PRRR_BINARY_PATH}"
    else
        log_warn "Pre-compiled binary not available, building from source..."

        # Ensure Rust toolchain is available
        if ! command -v cargo &>/dev/null; then
            log_step "Installing Rust toolchain..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
                sh -s -- -y --default-toolchain stable > /dev/null 2>&1
            # shellcheck source=/dev/null
            source "${HOME}/.cargo/env"
        fi

        cargo install prrr --git "${PRRR_GIT_REPO}" 2>/dev/null
        local cargo_bin
        cargo_bin="$(command -v prrr 2>/dev/null || echo "${HOME}/.cargo/bin/prrr")"
        if [[ -f "${cargo_bin}" ]]; then
            install -m 755 "${cargo_bin}" "${PRRR_BINARY_PATH}"
        fi
        log_info "Binary built and installed from source: ${PRRR_BINARY_PATH}"
    fi

    # Verify installation
    if [[ ! -x "${PRRR_BINARY_PATH}" ]]; then
        log_error "Binary installation failed: ${PRRR_BINARY_PATH} not found"
    fi
}

# ---------------------------------------------------------------------------
# Directory and config setup
# ---------------------------------------------------------------------------

setup_directories() {
    log_step "Creating directories..."
    mkdir -p "${PRRR_CONFIG_DIR}"
    mkdir -p "${PRRR_KEYS_DIR}"
    mkdir -p "${PRRR_TLS_DIR}"
    mkdir -p "${DATA_DIR}"
    mkdir -p "${PRRR_LOG_DIR}"

    chmod 700 "${PRRR_KEYS_DIR}"
    chmod 700 "${PRRR_TLS_DIR}"

    log_info "Directories created"
}

generate_admin_password() {
    if [[ -z "${ADMIN_PASS}" ]]; then
        ADMIN_PASS=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "${ADMIN_PASS_LENGTH}" || true)
        log_info "Admin password auto-generated"
    else
        log_info "Admin password provided via --admin-pass"
    fi

    # Save credentials file
    local creds_file="${PRRR_CONFIG_DIR}/admin_credentials.txt"
    cat > "${creds_file}" <<EOF
# prrr VPN Server Admin Credentials
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
#
# IMPORTANT: Keep this file secure. The password cannot be recovered.
#
Username: admin
Password: ${ADMIN_PASS}
EOF
    chmod 600 "${creds_file}"
    log_info "Admin credentials saved: ${creds_file}"
}

generate_config() {
    log_step "Generating server configuration..."

    # Format DNS servers for TOML array
    local dns_toml=""
    IFS=',' read -ra dns_array <<< "${DNS}"
    for i in "${!dns_array[@]}"; do
        if [[ "${i}" -gt 0 ]]; then
            dns_toml="${dns_toml}, "
        fi
        dns_toml="${dns_toml}\"${dns_array[$i]}\""
    done

    local config_file="${PRRR_CONFIG_DIR}/server.toml"

    # Determine web admin section
    local web_admin_section=""
    if [[ "${NO_WEB}" == false ]]; then
        web_admin_section="[web_admin]
enabled = true
listen_addr = \"0.0.0.0:${WEB_PORT}\"
# admin_password_hash will be set on first run
session_timeout = 3600"
    else
        web_admin_section="[web_admin]
enabled = false"
    fi

    cat > "${config_file}" <<EOF
# prrr VPN Server Configuration
# Generated by install-server.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Documentation: https://docs.prrr.dev

[server]
listen_addr = "0.0.0.0:${PORT}"
max_clients = ${MAX_CLIENTS}
log_level = "${LOG_LEVEL}"
data_dir = "${DATA_DIR}"
server_name = "www.google.com"

[network]
subnet = "${DEFAULT_SUBNET}"
dns_servers = [${dns_toml}]
mtu = 1280

[crypto]
identity_key_path = "${PRRR_KEYS_DIR}/server_identity.key"
pq_key_path = "${PRRR_KEYS_DIR}/server_pq.key"
rekey_interval = 3600

[transport]
protocol = "masque"
max_idle_timeout = 300
keep_alive = 25

[obfuscation]
enabled = true
padding_strategy = "power-of-two"
timing_jitter_ms = 50
tls_profile = "chrome"

[obfuscation.probe_resist]
enabled = true
psk = ""
tokens_per_second = 20
burst_capacity = 5

${web_admin_section}

[monitoring]
metrics_enabled = true
prometheus_port = 9090
log_file = "${PRRR_LOG_DIR}/server.log"
log_rotation = "daily"
log_retention_days = 7
EOF

    chmod 640 "${config_file}"
    log_info "Configuration generated: ${config_file}"
}

# ---------------------------------------------------------------------------
# Systemd service (SPEC.md §1.4)
# ---------------------------------------------------------------------------

install_systemd_service() {
    log_step "Installing systemd service..."

    cat > "${PRRR_SERVICE_FILE}" <<EOF
[Unit]
Description=prrr VPN Server
Documentation=https://docs.prrr.dev
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=notify
User=root
Group=root
ExecStart=${PRRR_BINARY_PATH} server --config ${PRRR_CONFIG_DIR}/server.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${PRRR_LOG_DIR}

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

# Capabilities (minimal)
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${PRRR_SERVICE_NAME}" > /dev/null 2>&1

    log_info "Systemd service installed and enabled: ${PRRR_SERVICE_FILE}"
}

# ---------------------------------------------------------------------------
# Firewall configuration (SPEC.md §1.5)
# ---------------------------------------------------------------------------

configure_firewall_ufw() {
    log_step "Configuring UFW firewall..."

    # Ensure SSH is allowed before enabling (prevent lockout)
    ufw allow 22/tcp comment "SSH" > /dev/null 2>&1

    # VPN port
    ufw allow "${PORT}/udp" comment "prrr VPN" > /dev/null 2>&1

    # Web admin port (if enabled)
    if [[ "${NO_WEB}" == false ]]; then
        ufw allow "${WEB_PORT}/tcp" comment "prrr Web Admin" > /dev/null 2>&1
    fi

    # Enable firewall
    ufw --force enable > /dev/null 2>&1

    log_info "UFW firewall configured"
}

configure_firewall_firewalld() {
    log_step "Configuring firewalld..."

    # Ensure firewalld is running
    systemctl start firewalld 2>/dev/null || true
    systemctl enable firewalld 2>/dev/null || true

    # VPN port
    firewall-cmd --permanent --add-port="${PORT}/udp" > /dev/null 2>&1

    # Web admin port (if enabled)
    if [[ "${NO_WEB}" == false ]]; then
        firewall-cmd --permanent --add-port="${WEB_PORT}/tcp" > /dev/null 2>&1
    fi

    # Masquerading for NAT
    firewall-cmd --permanent --add-masquerade > /dev/null 2>&1

    # IP forwarding rule
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -j ACCEPT > /dev/null 2>&1

    # Reload
    firewall-cmd --reload > /dev/null 2>&1

    log_info "firewalld configured"
}

configure_firewall() {
    case "${OS}" in
        ubuntu|debian)
            configure_firewall_ufw
            ;;
        fedora)
            configure_firewall_firewalld
            ;;
    esac
}

# ---------------------------------------------------------------------------
# IP forwarding
# ---------------------------------------------------------------------------

enable_ip_forwarding() {
    log_step "Enabling IP forwarding..."

    local sysctl_conf="/etc/sysctl.d/99-prrr.conf"
    cat > "${sysctl_conf}" <<EOF
# prrr VPN — IP forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF

    sysctl -p "${sysctl_conf}" > /dev/null 2>&1

    log_info "IP forwarding enabled"
}

# ---------------------------------------------------------------------------
# Installation output (SPEC.md §1.6)
# ---------------------------------------------------------------------------

print_success() {
    local server_ip
    server_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "0.0.0.0")

    local firewall_name
    case "${OS}" in
        ubuntu|debian) firewall_name="UFW" ;;
        fedora)        firewall_name="firewalld" ;;
        *)             firewall_name="unknown" ;;
    esac

    echo ""
    echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║              prrr VPN Server Installation Complete            ║${NC}"
    echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}✓${NC} Server binary installed: ${PRRR_BINARY_PATH}"
    echo -e "${GREEN}✓${NC} Configuration: ${PRRR_CONFIG_DIR}/server.toml"
    echo -e "${GREEN}✓${NC} Systemd service: ${PRRR_SERVICE_NAME}.service [enabled]"
    echo -e "${GREEN}✓${NC} Firewall configured: ${firewall_name} [active]"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " Server Connection Details"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if [[ -n "${DOMAIN}" ]]; then
        echo "Endpoint:        ${DOMAIN}:${PORT}"
    else
        echo "Endpoint:        ${server_ip}:${PORT}"
    fi

    echo ""

    if [[ "${NO_WEB}" == false ]]; then
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo " Web Admin Interface"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "URL:      https://${server_ip}:${WEB_PORT}"
        echo "Username: admin"
        echo "Password: ${ADMIN_PASS}"
        echo ""
        echo -e "${YELLOW}⚠ IMPORTANT: Save these credentials! They cannot be recovered.${NC}"
        echo "  Stored in: ${PRRR_CONFIG_DIR}/admin_credentials.txt"
    fi

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " Next Steps"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "1. Start the service: sudo systemctl start ${PRRR_SERVICE_NAME}"
    echo "2. Add clients: prrr server client add \"laptop\""
    echo "3. View logs: journalctl -u ${PRRR_SERVICE_NAME} -f"
    echo "4. Check status: systemctl status ${PRRR_SERVICE_NAME}"
    echo ""
    echo "Documentation: https://docs.prrr.dev"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${BOLD}prrr VPN Server Installer${NC}"
    echo ""

    parse_args "$@"

    log_step "Checking prerequisites..."
    check_root
    detect_os
    detect_arch
    check_system_requirements
    check_port_available "${PORT}" "udp" "VPN"
    if [[ "${NO_WEB}" == false ]]; then
        check_port_available "${WEB_PORT}" "tcp" "Web Admin"
    fi

    install_deps
    install_binary
    setup_directories
    generate_admin_password
    generate_config
    install_systemd_service
    configure_firewall
    enable_ip_forwarding

    print_success
}

main "$@"
