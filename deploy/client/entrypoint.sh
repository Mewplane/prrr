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
mtu = 1280

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

    # Register a test client and capture the private key from output
    log "Registering test client '${PRRR_CLIENT_NAME}'"
    local add_output
    add_output=$(prrr server --config "${SERVER_CONFIG}" --listen "${PRRR_LISTEN_ADDR}" \
        client add "${PRRR_CLIENT_NAME}" 2>/dev/null) || true
    echo "${add_output}"

    # Extract and save client private key (base64-encoded in output)
    local client_private_key_b64
    client_private_key_b64=$(echo "${add_output}" | grep 'Private Key:' | awk '{print $NF}')
    if [ -z "${client_private_key_b64}" ]; then
        log "ERROR: Failed to extract client private key from 'client add' output"
        exit 1
    fi

    local client_key_file="${PRRR_SHARED_DIR}/client_private.key"
    echo -n "${client_private_key_b64}" | base64 -d > "${client_key_file}"
    log "Client private key saved to ${client_key_file}"

    log "Exporting client config to ${CLIENT_CONFIG_SHARED}"
    prrr server --config "${SERVER_CONFIG}" --listen "${PRRR_LISTEN_ADDR}" \
        client export "${PRRR_CLIENT_NAME}" --output "${CLIENT_CONFIG_SHARED}"

    # Inject private_key_path into the existing [interface] section
    sed -i "/^\[interface\]/a private_key_path = \"${client_key_file}\"" "${CLIENT_CONFIG_SHARED}"
    log "Client config patched with private_key_path"

    # Signal readiness
    touch "${READY_MARKER}"
    log "Server ready (marker: ${READY_MARKER})"

    # Start the VPN server (exec replaces shell for signal forwarding)
    log "Starting prrr server on ${PRRR_LISTEN_ADDR}"
    exec prrr server --config "${SERVER_CONFIG}" --listen "${PRRR_LISTEN_ADDR}"
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

    # Transport selection (defaults to harp)
    local transport
    transport="${PRRR_TRANSPORT:-harp}"
    if [ "${transport}" = "masque" ]; then
        # Append [transport] section for MASQUE protocol
        cat >> "${CLIENT_CONFIG}" <<TRANSPORT_EOF

[transport]
protocol = "masque"
TRANSPORT_EOF
        log "Transport set to MASQUE"
    else
        log "Transport set to HARP (default)"
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
