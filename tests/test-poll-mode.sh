#!/bin/bash
# Test prrr HTTP polling mode without London VPN
set -euo pipefail

RESULTS="/tmp/prrr-poll-test-results.txt"
rm -f "$RESULTS"
exec > >(tee "$RESULTS") 2>&1

echo "=== prrr HTTP Polling Mode Test ==="
echo "Started: $(date)"

# Step 1: Disconnect London VPN
echo -e "\n--- Step 1: Disconnecting London VPN ---"
sudo systemctl stop openvpn-client@RUVDS-London 2>/dev/null || true
sleep 2
BARE_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || echo "FAILED")
echo "Bare IP (no VPN): $BARE_IP"

# Step 2: Start prrr client
echo -e "\n--- Step 2: Starting prrr client (polling mode) ---"
sudo /usr/local/bin/prrr client --config /etc/prrr/client.toml &
PRRR_PID=$!
echo "prrr PID: $PRRR_PID"

# Wait for connection
echo "Waiting for HARP session + routes..."
for i in $(seq 1 20); do
    if ip rule show 2>/dev/null | grep -q "fwmark"; then
        echo "fwmark rules appeared after ${i}s"
        break
    fi
    sleep 1
done

# Show routing state
echo -e "\n--- Routing state ---"
ip rule show | grep -E "fwmark|51820" || echo "No fwmark rules"
ip route show table 51820 2>/dev/null || echo "No table 51820"

# Show socket state
echo -e "\n--- Transport sockets ---"
ss -tnp 2>/dev/null | grep prrr || echo "No prrr TCP sockets"

# Step 3: Wait a bit for polling to stabilize
echo -e "\n--- Step 3: Waiting 5s for polling to stabilize ---"
sleep 5

# Show socket state again
echo -e "\n--- Transport sockets after 5s ---"
ss -tnp 2>/dev/null | grep prrr || echo "No prrr TCP sockets"

# Step 4: Traffic tests
echo -e "\n--- Step 4: Traffic tests ---"

echo -e "\n[Test 1] Ping gateway 10.66.66.1"
ping -c 4 -W 3 10.66.66.1 2>&1 || echo "Ping failed"

echo -e "\n[Test 2] DNS resolution"
dig +short +timeout=5 google.com 2>&1 || echo "DNS failed"

echo -e "\n[Test 3] curl ifconfig.me (should show droplet IP ~164.92.235.224)"
CURL_IP=$(curl -s --max-time 15 ifconfig.me 2>/dev/null || echo "FAILED")
echo "curl result: $CURL_IP"

echo -e "\n[Test 4] curl https://google.com"
curl -s --max-time 10 -o /dev/null -w "HTTP %{http_code}, %{time_total}s\n" https://google.com 2>&1 || echo "Google failed"

# Step 5: Final socket state
echo -e "\n--- Final socket state ---"
ss -tnp 2>/dev/null | grep prrr || echo "No prrr TCP sockets"

# Step 6: Stop prrr
echo -e "\n--- Step 6: Stopping prrr ---"
sudo kill "$PRRR_PID" 2>/dev/null || true
wait "$PRRR_PID" 2>/dev/null || true
sleep 2

# Step 7: Restore London VPN
echo -e "\n--- Step 7: Restoring London VPN ---"
sudo systemctl start openvpn-client@RUVDS-London
sleep 3
RESTORED_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || echo "FAILED")
echo "Restored IP: $RESTORED_IP"

echo -e "\n=== Test complete: $(date) ==="
