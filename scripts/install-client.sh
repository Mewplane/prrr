#!/usr/bin/env bash
# FRD: specs/frds/FRD-P011.md
# prrr VPN Client Installation Script
# SPEC.md §2.1 — Client installation
#
# Usage:
#   curl -fsSL https://install.prrr.dev/client | bash
#
# This script does NOT require root for the main installation.
# Root/sudo is only needed for installing system dependencies.

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

readonly PRRR_VERSION="latest"
readonly PRRR_BINARY_NAME="prrr"
readonly PRRR_BINARY_PATH="/usr/local/bin/prrr"
readonly PRRR_DOWNLOAD_BASE="https://github.com/prrr-vpn/releases"
readonly PRRR_GIT_REPO="https://github.com/prrr-vpn/prrr"

readonly CLIENT_CONFIG_DIR="${HOME}/.config/prrr"
readonly CLIENT_DATA_DIR="${HOME}/.local/share/prrr"
readonly CLIENT_KEYS_DIR="${CLIENT_DATA_DIR}/keys"
readonly CLIENT_LOGS_DIR="${CLIENT_DATA_DIR}/logs"

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
# Environment detection
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
# Dependency installation
# ---------------------------------------------------------------------------

install_deps_apt() {
    log_step "Installing dependencies via apt..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        curl \
        > /dev/null 2>&1
    log_info "Dependencies installed (apt)"
}

install_deps_dnf() {
    log_step "Installing dependencies via dnf..."
    sudo dnf install -y -q \
        curl \
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
# Binary installation
# ---------------------------------------------------------------------------

install_binary() {
    log_step "Installing prrr client..."

    # Try pre-compiled binary first
    local download_url="${PRRR_DOWNLOAD_BASE}/${PRRR_VERSION}/${PRRR_BINARY_NAME}-${ARCH}"

    if curl -fsSL "${download_url}" -o "/tmp/${PRRR_BINARY_NAME}" 2>/dev/null; then
        sudo install -m 755 "/tmp/${PRRR_BINARY_NAME}" "${PRRR_BINARY_PATH}"
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
        log_info "Binary built and installed from source"
    fi

    # Verify installation
    if ! command -v prrr &>/dev/null; then
        log_error "Binary installation failed: prrr not found in PATH"
    fi
}

# ---------------------------------------------------------------------------
# Directory setup (SPEC.md §2.1)
# ---------------------------------------------------------------------------

setup_directories() {
    log_step "Setting up client directories..."

    mkdir -p "${CLIENT_CONFIG_DIR}"
    mkdir -p "${CLIENT_KEYS_DIR}"
    mkdir -p "${CLIENT_LOGS_DIR}"

    chmod 700 "${CLIENT_CONFIG_DIR}"
    chmod 700 "${CLIENT_KEYS_DIR}"

    log_info "Client directories created"
}

# ---------------------------------------------------------------------------
# Installation output
# ---------------------------------------------------------------------------

print_success() {
    echo ""
    echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║            prrr VPN Client Installation Complete             ║${NC}"
    echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}✓${NC} Client binary installed"
    echo -e "${GREEN}✓${NC} Config directory: ${CLIENT_CONFIG_DIR}"
    echo -e "${GREEN}✓${NC} Keys directory: ${CLIENT_KEYS_DIR}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " Next Steps"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "1. Get connection config from server admin"
    echo "2. Import config: prrr client import config.toml"
    echo "3. Or import from URL: prrr client import \"prrr://import?config=...\""
    echo "4. Run diagnostics: prrr client doctor"
    echo ""
    echo "Documentation: https://docs.prrr.dev/client"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${BOLD}prrr VPN Client Installer${NC}"
    echo ""

    detect_os
    detect_arch
    install_deps
    install_binary
    setup_directories
    print_success
}

main
