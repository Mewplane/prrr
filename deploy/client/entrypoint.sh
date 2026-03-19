#!/usr/bin/env bash
# Entrypoint for prrr E2E test container.
#
# Modes (via PRRR_MODE env var):
#   server  — Generate keys, write config, register test client, start server
#   client  — Wait for shared client config, start client
#
# Environment variables:
#   PRRR_MODE           server|client (required)
#   PRRR_LISTEN_ADDR    Server listen address (default: 0.0.0.0:443)
#   PRRR_SUBNET         VPN subnet CIDR (default: 10.66.66.0/24)
#   PRRR_MAX_CLIENTS    Max concurrent clients (default: 10)
#   PRRR_LOG_LEVEL      Log level (default: debug)
#   PRRR_DATA_DIR       Server data directory (default: /var/lib/prrr)
#   PRRR_SHARED_DIR     Shared volume for config exchange (default: /shared)
#   PRRR_CLIENT_NAME    Test client name (default: e2e-test-client)
#   PRRR_SERVER_NAME    TLS SNI server name for client (default: localhost)
#   PRRR_SERVER_ENDPOINT  Server address for client (default: 127.0.0.1:443)
#   PRRR_TRANSPORT      Client transport protocol: harp|masque (default: harp)

set -euo pipefail

PRRR_MODE="${PRRR_MODE:?PRRR_MODE must be set to 'server' or 'client'}"
PRRR_LISTEN_ADDR="${PRRR_LISTEN_ADDR:-0.0.0.0:443}"
PRRR_SUBNET="${PRRR_SUBNET:-10.66.66.0/24}"
PRRR_MAX_CLIENTS="${PRRR_MAX_CLIENTS:-10}"
PRRR_LOG_LEVEL="${PRRR_LOG_LEVEL:-debug}"
PRRR_DATA_DIR="${PRRR_DATA_DIR:-/var/lib/prrr}"
PRRR_SHARED_DIR="${PRRR_SHARED_DIR:-/shared}"
PRRR_CLIENT_NAME="${PRRR_CLIENT_NAME:-e2e-test-client}"

SERVER_CONFIG="/etc/prrr/server.toml"
CLIENT_CONFIG="/etc/prrr/client.toml"
READY_MARKER="${PRRR_SHARED_DIR}/server-ready"
CLIENT_CONFIG_SHARED="${PRRR_SHARED_DIR}/client.toml"
WAIT_TIMEOUT_SECS=60

log() {
    echo "[entrypoint] $*"
}

run_server() {
    log "Starting in SERVER mode"

    mkdir -p /etc/prrr/keys "${PRRR_DATA_DIR}" "${PRRR_SHARED_DIR}"

    # Write server config
    cat > "${SERVER_CONFIG}" <<EOF
[server]
listen_addr = "${PRRR_LISTEN_ADDR}"
max_clients = ${PRRR_MAX_CLIENTS}
log_level = "${PRRR_LOG_LEVEL}"
data_dir = "${PRRR_DATA_DIR}"
server_name = "localhost"

[network]
subnet = "${PRRR_SUBNET}"
dns_servers = ["1.1.1.1", "8.8.8.8"]
mtu = 1100

[crypto]
identity_key_path = "/etc/prrr/keys/server_identity.key"
pq_key_path = "/etc/prrr/keys/server_pq.key"

[[transports]]
name = "masque"
enabled = true

[[transports]]
name = "harp"
enabled = true
websocket_enabled = true
polling_enabled = true

[obfuscation]
enabled = false
EOF

    log "Server config written to ${SERVER_CONFIG}"

    # Register a test client — outputs complete config (with inline private_key) to stdout
    log "Registering test client '${PRRR_CLIENT_NAME}'"
    prrr server --config "${SERVER_CONFIG}" --listen "${PRRR_LISTEN_ADDR}" \
        client add "${PRRR_CLIENT_NAME}" > "${CLIENT_CONFIG_SHARED}"
    log "Client config saved to ${CLIENT_CONFIG_SHARED}"

    # Signal readiness
    touch "${READY_MARKER}"
    log "Server ready (marker: ${READY_MARKER})"

    # Start the VPN server — tee logs to shared volume for test-runner access
    log "Starting prrr server on ${PRRR_LISTEN_ADDR}"
    prrr server --config "${SERVER_CONFIG}" --listen "${PRRR_LISTEN_ADDR}" 2>&1 | tee "${PRRR_SHARED_DIR}/server.log" &
    SERVER_PID=$!
    trap "kill ${SERVER_PID} 2>/dev/null; wait ${SERVER_PID} 2>/dev/null" EXIT
    wait "${SERVER_PID}"
}

run_client() {
    log "Starting in CLIENT mode"

    mkdir -p /etc/prrr "${PRRR_SHARED_DIR}"

    # Wait for server to export client config
    log "Waiting for client config at ${CLIENT_CONFIG_SHARED} (timeout: ${WAIT_TIMEOUT_SECS}s)"
    elapsed=0
    while [ ! -f "${CLIENT_CONFIG_SHARED}" ]; do
        if [ "${elapsed}" -ge "${WAIT_TIMEOUT_SECS}" ]; then
            log "ERROR: Timed out waiting for client config"
            exit 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    # Copy shared config to local path
    cp "${CLIENT_CONFIG_SHARED}" "${CLIENT_CONFIG}"
    log "Client config copied to ${CLIENT_CONFIG}"

    # Patch the server endpoint (set via PRRR_SERVER_ENDPOINT or default to 127.0.0.1:443)
    local server_endpoint
    server_endpoint="${PRRR_SERVER_ENDPOINT:-127.0.0.1:443}"
    if grep -q 'endpoint' "${CLIENT_CONFIG}"; then
        sed -i "s/endpoint = .*/endpoint = \"${server_endpoint}\"/" "${CLIENT_CONFIG}"
    fi
    log "Server endpoint patched to ${server_endpoint}"

    # Transport selection (override if PRRR_TRANSPORT is set)
    local transport
    transport="${PRRR_TRANSPORT:-}"
    if [ -n "${transport}" ]; then
        sed -i "s/transport_protocol = .*/transport_protocol = \"${transport}\"/" "${CLIENT_CONFIG}"
        log "Transport set to ${transport}"
    fi

    # Resolve server name for TLS SNI (defaults to localhost for pod networking)
    local server_name
    server_name="${PRRR_SERVER_NAME:-localhost}"

    # Start the VPN client with --insecure (self-signed cert)
    log "Starting prrr client (transport=${transport}, server-name=${server_name})"
    exec prrr client --config "${CLIENT_CONFIG}" --insecure --server-name "${server_name}"
}

case "${PRRR_MODE}" in
    server)
        run_server
        ;;
    client)
        run_client
        ;;
    *)
        log "ERROR: Unknown PRRR_MODE='${PRRR_MODE}'. Use 'server' or 'client'."
        exit 1
        ;;
esac
