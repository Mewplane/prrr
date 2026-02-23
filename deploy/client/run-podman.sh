#!/usr/bin/env bash
# Podman E2E test orchestrator for prrr VPN.
#
# Builds the container image, launches server + client on a shared network
# (each with its own network namespace for TUN device isolation), runs
# connectivity tests, and cleans up.
#
# Usage:
#   ./deploy/client/run-podman.sh
#
# Environment variables:
#   PRRR_IMAGE_NAME     Container image name (default: prrr-e2e)
#   PRRR_IMAGE_TAG      Container image tag (default: latest)
#   PRRR_POD_NAME       Pod name prefix (default: prrr-e2e-pod)
#   PRRR_SUBNET         VPN subnet CIDR (default: 10.66.66.0/24)
#   PRRR_LISTEN_PORT    Server listen port (default: 443)
#   PRRR_LOG_LEVEL      Log level (default: debug)
#   PRRR_STARTUP_WAIT   Seconds to wait for server startup (default: 15)
#   PRRR_CLIENT_WAIT    Seconds to wait for client connection (default: 30)
#   PRRR_TEST_TIMEOUT   Seconds for connectivity test (default: 10)
#   PRRR_SKIP_BUILD     Set to 1 to skip image build (default: 0)
#   PRRR_TRANSPORT      Client transport protocol: harp|masque (default: harp)

set -euo pipefail

PRRR_IMAGE_NAME="${PRRR_IMAGE_NAME:-prrr-e2e}"
PRRR_IMAGE_TAG="${PRRR_IMAGE_TAG:-latest}"
PRRR_POD_NAME="${PRRR_POD_NAME:-prrr-e2e-pod}"
PRRR_SUBNET="${PRRR_SUBNET:-10.66.66.0/24}"
PRRR_LISTEN_PORT="${PRRR_LISTEN_PORT:-443}"
PRRR_LOG_LEVEL="${PRRR_LOG_LEVEL:-debug}"
PRRR_STARTUP_WAIT="${PRRR_STARTUP_WAIT:-15}"
PRRR_CLIENT_WAIT="${PRRR_CLIENT_WAIT:-30}"
PRRR_TEST_TIMEOUT="${PRRR_TEST_TIMEOUT:-10}"
PRRR_SKIP_BUILD="${PRRR_SKIP_BUILD:-0}"
PRRR_TRANSPORT="${PRRR_TRANSPORT:-harp}"

IMAGE="${PRRR_IMAGE_NAME}:${PRRR_IMAGE_TAG}"
SERVER_CTR="${PRRR_POD_NAME}-server"
CLIENT_CTR="${PRRR_POD_NAME}-client"
NETWORK_NAME="${PRRR_POD_NAME}-net"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/../.."

# Track exit code for cleanup
EXIT_CODE=1

log() {
    echo "[e2e] $(date '+%H:%M:%S') $*"
}

cleanup() {
    log "Cleaning up..."
    podman rm -f "${SERVER_CTR}" "${CLIENT_CTR}" 2>/dev/null || true
    podman volume rm "${PRRR_POD_NAME}-shared" 2>/dev/null || true
    podman network rm "${NETWORK_NAME}" 2>/dev/null || true
    log "Cleanup complete"
    exit "${EXIT_CODE}"
}

trap cleanup EXIT

# ---------- Step 1: Build image ----------
if [ "${PRRR_SKIP_BUILD}" != "1" ]; then
    log "Building container image ${IMAGE}..."
    podman build \
        -t "${IMAGE}" \
        -f deploy/client/Containerfile \
        "${PROJECT_ROOT}"
    log "Image built successfully"
else
    log "Skipping build (PRRR_SKIP_BUILD=1)"
fi

# Verify image exists
if ! podman image exists "${IMAGE}"; then
    log "ERROR: Image ${IMAGE} not found"
    exit 1
fi

# Check image size
IMAGE_SIZE_MB=$(podman image inspect "${IMAGE}" --format '{{.Size}}' | awk '{printf "%.0f", $1/1048576}')
log "Image size: ${IMAGE_SIZE_MB}MB"

# ---------- Step 2: Create network and shared volume ----------
log "Creating network ${NETWORK_NAME} and shared volume..."
podman rm -f "${SERVER_CTR}" "${CLIENT_CTR}" 2>/dev/null || true
podman volume rm "${PRRR_POD_NAME}-shared" 2>/dev/null || true
podman network rm "${NETWORK_NAME}" 2>/dev/null || true

podman volume create "${PRRR_POD_NAME}-shared"
podman network create "${NETWORK_NAME}"

# ---------- Step 3: Start server ----------
log "Starting server container..."
podman run -d \
    --name "${SERVER_CTR}" \
    --network "${NETWORK_NAME}" \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --device=/dev/net/tun \
    --security-opt label=disable \
    -v "${PRRR_POD_NAME}-shared:/shared:z" \
    -e PRRR_MODE=server \
    -e PRRR_LISTEN_ADDR="0.0.0.0:${PRRR_LISTEN_PORT}" \
    -e PRRR_SUBNET="${PRRR_SUBNET}" \
    -e PRRR_LOG_LEVEL="${PRRR_LOG_LEVEL}" \
    "${IMAGE}"

# Wait for server readiness (checks for the ready marker file)
log "Waiting for server readiness (timeout: ${PRRR_STARTUP_WAIT}s)..."
elapsed=0
while ! podman exec "${SERVER_CTR}" test -f /shared/server-ready 2>/dev/null; do
    if [ "${elapsed}" -ge "${PRRR_STARTUP_WAIT}" ]; then
        log "ERROR: Server failed to start within ${PRRR_STARTUP_WAIT}s"
        log "Server logs:"
        podman logs "${SERVER_CTR}" 2>&1 | tail -30
        exit 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done
log "Server is ready (${elapsed}s)"

# Verify client config was exported
if ! podman exec "${SERVER_CTR}" test -f /shared/client.toml; then
    log "ERROR: Client config not found in shared volume"
    podman logs "${SERVER_CTR}" 2>&1 | tail -20
    exit 1
fi

# Resolve the server's container IP on the podman network
SERVER_IP=$(podman inspect "${SERVER_CTR}" --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
log "Server container IP: ${SERVER_IP}"

# ---------- Step 4: Start client ----------
log "Starting client container (transport=${PRRR_TRANSPORT})..."
podman run -d \
    --name "${CLIENT_CTR}" \
    --network "${NETWORK_NAME}" \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --device=/dev/net/tun \
    --security-opt label=disable \
    -v "${PRRR_POD_NAME}-shared:/shared:z" \
    -e PRRR_MODE=client \
    -e PRRR_LOG_LEVEL="${PRRR_LOG_LEVEL}" \
    -e PRRR_SERVER_ENDPOINT="${SERVER_IP}:${PRRR_LISTEN_PORT}" \
    -e PRRR_TRANSPORT="${PRRR_TRANSPORT}" \
    "${IMAGE}"

# Wait for client to establish tunnel
log "Waiting for client tunnel establishment (timeout: ${PRRR_CLIENT_WAIT}s)..."
elapsed=0
tunnel_up=false
while [ "${elapsed}" -lt "${PRRR_CLIENT_WAIT}" ]; do
    # Check if client has a TUN device
    if podman exec "${CLIENT_CTR}" ip link show type tun 2>/dev/null | grep -q "prrr\|tun"; then
        tunnel_up=true
        break
    fi
    # Also check if client process is still running
    if ! podman exec "${CLIENT_CTR}" pgrep -x prrr >/dev/null 2>&1; then
        log "WARNING: Client process exited, checking logs..."
        podman logs "${CLIENT_CTR}" 2>&1 | tail -20
        # Don't fail immediately — client might be restarting
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

if [ "${tunnel_up}" = true ]; then
    log "Client tunnel established (${elapsed}s)"
else
    log "WARNING: Could not detect TUN device after ${PRRR_CLIENT_WAIT}s"
    log "Client logs:"
    podman logs "${CLIENT_CTR}" 2>&1 | tail -30
    log "Continuing with connectivity test anyway..."
fi

# ---------- Step 5: Connectivity test ----------
# Allow a brief settle time for tunnel pipeline to start processing packets
sleep 2
log "Running connectivity test..."

# Extract client VPN IP from config (first client gets .2 in the subnet)
CLIENT_VPN_IP="10.66.66.2"
SERVER_VPN_IP="10.66.66.1"

# Test: client can reach the server's VPN gateway IP
test_passed=false
if podman exec "${CLIENT_CTR}" ping -c 1 -W "${PRRR_TEST_TIMEOUT}" "${SERVER_VPN_IP}" >/dev/null 2>&1; then
    log "PASS: Client can ping server VPN gateway (${SERVER_VPN_IP})"
    test_passed=true
else
    log "FAIL: Client cannot ping server VPN gateway (${SERVER_VPN_IP})"
    log "Client routes:"
    podman exec "${CLIENT_CTR}" ip route 2>/dev/null || true
    log "Client interfaces:"
    podman exec "${CLIENT_CTR}" ip addr 2>/dev/null || true
    log "Server interfaces:"
    podman exec "${SERVER_CTR}" ip addr 2>/dev/null || true
fi

# Test: server can reach the client's VPN IP
if podman exec "${SERVER_CTR}" ping -c 1 -W "${PRRR_TEST_TIMEOUT}" "${CLIENT_VPN_IP}" >/dev/null 2>&1; then
    log "PASS: Server can ping client VPN IP (${CLIENT_VPN_IP})"
else
    log "FAIL: Server cannot ping client VPN IP (${CLIENT_VPN_IP})"
    test_passed=false
fi

# ---------- Step 6: Report results ----------
echo ""
echo "========================================="
if [ "${test_passed}" = true ]; then
    echo "  E2E TEST RESULT: PASS"
    EXIT_CODE=0
else
    echo "  E2E TEST RESULT: FAIL"
    echo ""
    echo "  Server logs (last 20 lines):"
    podman logs "${SERVER_CTR}" 2>&1 | tail -20 | sed 's/^/    /'
    echo ""
    echo "  Client logs (last 20 lines):"
    podman logs "${CLIENT_CTR}" 2>&1 | tail -20 | sed 's/^/    /'
    EXIT_CODE=1
fi
echo "========================================="
echo ""
