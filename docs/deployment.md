# Deployment Guide

This guide covers production deployment of prrr VPN servers with HTTPS-secured admin panel, automatic certificate management, and monitoring.

## Prerequisites

- **Server**: Ubuntu 22.04+, Debian 11+, or Fedora 38+ with root access
- **Domain**: A registered domain with DNS access (for Let's Encrypt certificates)
- **Ports**: TCP 443 (HARP VPN), UDP 443 (MASQUE VPN, optional), TCP 80 (Let's Encrypt validation), TCP 9443 (HTTPS admin panel)
- **Client**: Rust 1.85+ for building from source, or use installation script

## Deployment Options

### Option 1: Installation Script (Recommended)

The installation script automates the complete deployment with Let's Encrypt HTTPS certificates and nginx reverse proxy.

**Prerequisites:**
- Domain name pointing to your server's IP
- Root access to the server
- Ports 80, 443, and 9443 available

**Installation:**

```bash
curl -fsSL https://raw.githubusercontent.com/prrr-vpn/prrr/main/deploy/scripts/install-server.sh | sudo bash -s -- \
  --domain prrr.example.com \
  --admin-pass "your-secure-password"
```

Or download and run locally:

```bash
wget https://raw.githubusercontent.com/prrr-vpn/prrr/main/deploy/scripts/install-server.sh
chmod +x install-server.sh
sudo ./install-server.sh --domain prrr.example.com --admin-pass "your-secure-password"
```

**What the script does:**

1. Installs dependencies (certbot, nginx, argon2)
2. Obtains Let's Encrypt certificates for your domain
3. Configures nginx as HTTPS reverse proxy on port 9443
4. Generates secure password hash and PSK
5. Creates prrr configuration with web admin enabled
6. Sets up systemd service for automatic startup
7. Configures firewall rules (UDP 443, TCP 80, TCP 9443)
8. Enables IP forwarding and NAT for VPN clients

**Supported Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--domain DOMAIN` | **required** | Domain name for Let's Encrypt certificates |
| `--admin-pass PASSWORD` | auto-generated | Web admin password |
| `--vpn-port PORT` | `443` | VPN listen port (TCP for HARP, UDP for MASQUE) |
| `--admin-port PORT` | `9443` | HTTPS admin panel port (TCP) |
| `--no-certbot` | `false` | Skip Let's Encrypt setup (use existing certs) |
| `--email EMAIL` | -- | Email for Let's Encrypt notifications |

**After Installation:**

The script outputs the admin panel URL and credentials:

```
✓ Installation complete!

  Admin Panel: https://admin.prrr.example.com:9443
  Username:    admin
  Password:    your-secure-password

  VPN Endpoint: prrr.example.com:443

  Next steps:
  1. Access admin panel to add VPN clients
  2. Certificates auto-renew via certbot systemd timer
  3. Check status: systemctl status prrr
```

### Option 2: Terraform (DigitalOcean)

Deploy infrastructure and server in one command.

**Prerequisites:**
- DigitalOcean account and API token
- Domain configured with DigitalOcean DNS
- SSH key added to DigitalOcean

**Deployment:**

```bash
cd deploy/terraform

cat > terraform.tfvars <<EOF
do_token            = "dop_v1_your_token"
ssh_key_ids         = [12345678]
admin_password      = "your-secure-password"
domain              = "prrr.example.com"
admin_subdomain     = "admin"
certbot_email       = "you@example.com"
admin_ip_addresses  = ["YOUR_IP/32"]
EOF

terraform init
terraform plan
terraform apply
```

**After Terraform completes:**

The droplet is provisioned with DNS records and firewall rules, but you need to install prrr:

```bash
# Build static binary locally
cargo build --release --target x86_64-unknown-linux-musl

# Get server IP from Terraform
SERVER_IP=$(terraform output -raw server_ip)

# Upload binary
scp target/x86_64-unknown-linux-musl/release/prrr root@$SERVER_IP:/usr/local/bin/

# SSH to server and run installation script
ssh root@$SERVER_IP
curl -fsSL https://raw.githubusercontent.com/prrr-vpn/prrr/main/deploy/scripts/install-server.sh | bash -s -- \
  --domain prrr.example.com \
  --admin-pass "your-secure-password"
```

**Terraform Outputs:**

```bash
terraform output web_admin_url        # HTTPS admin panel URL
terraform output vpn_endpoint         # VPN server endpoint
terraform output admin_credentials    # Admin username/password
terraform output dns_records          # DNS records created
```

See [deploy/terraform/README.md](../deploy/terraform/README.md) for full details.

### Option 3: Manual Setup

For custom environments or non-supported distributions.

#### Step 1: Install dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y certbot nginx argon2 iptables

# Fedora
sudo dnf install -y certbot nginx argon2 iptables
```

#### Step 2: Build and install prrr

```bash
# Build static binary
git clone https://github.com/prrr-vpn/prrr.git
cd prrr
cargo build --release --target x86_64-unknown-linux-musl

# Install
sudo cp target/x86_64-unknown-linux-musl/release/prrr /usr/local/bin/
sudo chmod +x /usr/local/bin/prrr
```

#### Step 3: Configure DNS

Create A records for your domain:

```bash
# Example using DigitalOcean CLI (doctl)
doctl compute domain records create prrr.example.com \
  --record-type A \
  --record-name @ \
  --record-data YOUR_SERVER_IP \
  --record-ttl 300

doctl compute domain records create prrr.example.com \
  --record-type A \
  --record-name admin \
  --record-data YOUR_SERVER_IP \
  --record-ttl 300
```

Wait 60 seconds for DNS propagation:

```bash
dig +short prrr.example.com
dig +short admin.prrr.example.com
```

#### Step 4: Obtain Let's Encrypt certificates

```bash
sudo certbot certonly --standalone \
  -d prrr.example.com \
  -d admin.prrr.example.com \
  --email you@example.com \
  --agree-tos \
  --non-interactive
```

Certificates are saved to `/etc/letsencrypt/live/prrr.example.com/`.

#### Step 5: Generate admin password hash

```bash
SALT=$(openssl rand -base64 16)
HASH=$(echo -n "your-password" | argon2 "$SALT" -id -t 3 -m 16 -p 1 -e)
echo "$HASH"
```

Copy the hash for the next step.

#### Step 6: Create prrr configuration

Create `/etc/prrr/server.toml`:

```toml
[server]
listen_address = "0.0.0.0:443"
server_name = "prrr.example.com"
max_clients = 100

[network]
subnet = "10.66.66.0/24"
gateway = "10.66.66.1"
dns_servers = ["1.1.1.1", "8.8.8.8"]

[[transports]]
name = "harp"
websocket_enabled = true
polling_enabled = true

[[transports]]
name = "masque"
tls_cert = "/etc/letsencrypt/live/prrr.example.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/prrr.example.com/privkey.pem"

[keys]
server_key_path = "/etc/prrr/keys/server.key"
kem_key_path = "/etc/prrr/keys/server_kem.key"
psk_path = "/etc/prrr/keys/psk.key"

[database]
path = "/var/lib/prrr/clients.db"

[web_admin]
enabled = true
listen = "127.0.0.1:8443"
admin_password_hash = '$argon2id$v=19$m=65536,t=3,p=1$YOUR_HASH_HERE'
session_timeout = 3600

[obfuscation]
tls_profile = "chrome"
padding_strategy = "http-sizes"
max_jitter_ms = 50
enable_probe_resistance = true

[logging]
level = "info"
```

**Important:** Use single quotes around `admin_password_hash` to preserve the `$` characters.

Create directories:

```bash
sudo mkdir -p /etc/prrr/keys /var/lib/prrr
```

#### Step 7: Configure nginx reverse proxy

Create `/etc/nginx/sites-available/prrr-admin`:

```nginx
server {
    listen 9443 ssl http2;
    server_name admin.prrr.example.com;

    ssl_certificate /etc/letsencrypt/live/prrr.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/prrr.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/prrr-admin /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

#### Step 8: Create systemd service

Create `/etc/systemd/system/prrr.service`:

```ini
[Unit]
Description=prrr VPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/prrr server --config /etc/prrr/server.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/prrr /etc/prrr/keys
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable prrr
sudo systemctl start prrr
```

#### Step 9: Configure firewall

```bash
# Ubuntu/Debian (ufw)
sudo ufw allow 443/tcp comment 'prrr VPN (HARP)'
sudo ufw allow 443/udp comment 'prrr VPN (MASQUE)'
sudo ufw allow 80/tcp comment 'Let\'s Encrypt'
sudo ufw allow 9443/tcp comment 'prrr Admin HTTPS'

# Fedora (firewalld)
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=443/udp
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=9443/tcp
sudo firewall-cmd --reload

# Or using iptables directly
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9443 -j ACCEPT
```

#### Step 10: Enable IP forwarding and NAT

```bash
# Enable IP forwarding (persist across reboots)
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-prrr.conf
sudo sysctl -p /etc/sysctl.d/99-prrr.conf

# Set up NAT (replace eth0 with your interface)
INTERFACE=$(ip route show default | awk '{print $5}')
sudo iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o $INTERFACE -j MASQUERADE
sudo iptables -A FORWARD -i prrr+ -o $INTERFACE -j ACCEPT
sudo iptables -A FORWARD -i $INTERFACE -o prrr+ -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save iptables rules (Ubuntu/Debian)
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save

# Save iptables rules (Fedora)
sudo iptables-save | sudo tee /etc/sysconfig/iptables
```

#### Step 11: Verify installation

```bash
# Check service status
sudo systemctl status prrr
sudo systemctl status nginx

# Check ports
sudo ss -tlnp | grep 443     # VPN — HARP (TCP)
sudo ss -ulnp | grep 443     # VPN — MASQUE (UDP), if enabled
sudo ss -tlnp | grep 8443    # prrr admin (HTTP, localhost only)
sudo ss -tlnp | grep 9443    # nginx (HTTPS, public)

# Check logs
sudo journalctl -u prrr -f
sudo journalctl -u nginx -f
```

Access admin panel at: `https://admin.prrr.example.com:9443`

## Certificate Management

### Auto-Renewal

Let's Encrypt certificates expire after 90 days. Certbot installs a systemd timer for automatic renewal.

**Check timer status:**

```bash
sudo systemctl status certbot.timer
```

**Test renewal (dry run):**

```bash
sudo certbot renew --dry-run
```

**Manual renewal:**

```bash
sudo certbot renew
sudo systemctl reload nginx
```

### Renewal Hook

To automatically reload nginx after renewal, create `/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh`:

```bash
#!/bin/bash
systemctl reload nginx
```

Make it executable:

```bash
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

## Monitoring

### Systemd Status

```bash
sudo systemctl status prrr
sudo journalctl -u prrr -f --lines 100
```

### Prometheus Metrics

Add to `/etc/prrr/server.toml`:

```toml
[monitoring]
metrics_enabled = true
prometheus_port = 9090
```

Scrape `http://localhost:9090/metrics` with Prometheus.

**Example metrics:**
- `prrr_active_connections` - Current VPN connections
- `prrr_bytes_sent_total` - Total bytes sent
- `prrr_bytes_received_total` - Total bytes received
- `prrr_handshakes_total` - Total successful handshakes
- `prrr_handshake_failures_total` - Failed handshake attempts

### Health Check

```bash
curl http://localhost:9090/health
```

Returns JSON:
```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "active_clients": 5,
  "version": "0.1.0"
}
```

## Security Hardening

### Restrict Admin Access by IP

Update firewall to allow admin access only from your IP:

```bash
# Ubuntu/Debian (ufw)
sudo ufw delete allow 9443/tcp
sudo ufw allow from YOUR_IP/32 to any port 9443 proto tcp

# Fedora (firewalld)
sudo firewall-cmd --permanent --remove-port=9443/tcp
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="YOUR_IP/32" port port="9443" protocol="tcp" accept'
sudo firewall-cmd --reload
```

Or configure in Terraform:

```hcl
admin_ip_addresses = ["YOUR_IP/32"]
```

### Fail2Ban

Install fail2ban to block brute-force attacks on the admin panel:

```bash
sudo apt-get install -y fail2ban

# Create filter
sudo tee /etc/fail2ban/filter.d/prrr-admin.conf <<EOF
[Definition]
failregex = ^.*prrr::web_admin.*authentication failed.*from <HOST>.*$
ignoreregex =
EOF

# Create jail
sudo tee /etc/fail2ban/jail.d/prrr-admin.conf <<EOF
[prrr-admin]
enabled = true
port = 9443
filter = prrr-admin
logpath = /var/log/syslog
maxretry = 5
bantime = 3600
EOF

sudo systemctl restart fail2ban
```

### SSH Key-Only Authentication

Disable password authentication:

```bash
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

## Podman E2E Testing

The project includes a containerized end-to-end test environment using Podman. This creates a real VPN tunnel between a server and client running in separate containers, validating the full connection lifecycle without requiring host-level privileges beyond what Podman needs.

### Prerequisites

- **Podman** 4.0+ (rootless mode supported)
- **Linux kernel** with TUN/TAP support (`/dev/net/tun`)
- **SELinux note**: On Fedora/RHEL, the test script uses `--security-opt label=disable` to allow TUN device access in rootless containers

### Quick Start

```bash
# Build the container image
make podman-build

# Run the full E2E test (both MASQUE and HARP transports)
make podman-e2e

# Run individual transports
make podman-e2e-masque    # MASQUE/QUIC only
make podman-e2e-harp      # HARP/HTTP+WebSocket only
make podman-e2e-multi     # Both transports sequentially
```

### What the E2E Test Validates

1. **Container image build** — Multi-stage Dockerfile compiles prrr from source
2. **Server startup** — Server generates keys, enables both MASQUE and HARP transports
3. **Client registration** — `prrr server client add` registers a test client and exports its config
4. **Key distribution** — Private key is captured from server output and injected into client config
5. **Transport selection** — Client selects MASQUE or HARP based on `PRRR_TRANSPORT` env var
6. **Tunnel creation** — Both containers create TUN devices (`prrr0`) in their own network namespaces
7. **Bidirectional connectivity** — Client pings server VPN gateway, server pings client VPN IP

### Architecture

The test uses `podman network create` (not a pod) so each container has its own network namespace. This is required because both server and client create a TUN device named `prrr0` — sharing a network namespace would cause `EBUSY` conflicts.

```
┌─────────────────────────────────────────────────┐
│              Podman Network (bridge)             │
│                                                  │
│  ┌──────────────┐         ┌──────────────┐       │
│  │   Server      │         │   Client      │      │
│  │  10.89.x.2    │◄───────►│  10.89.x.3    │      │
│  │               │  QUIC   │               │      │
│  │  TUN: prrr0   │         │  TUN: prrr0   │      │
│  │  10.66.66.1   │◄ ─ ─ ─►│  10.66.66.2   │      │
│  └──────────────┘  tunnel  └──────────────┘       │
└─────────────────────────────────────────────────┘
```

### Container Capabilities

The containers require specific Linux capabilities:

| Capability | Purpose |
|---|---|
| `CAP_NET_ADMIN` | Create and configure TUN devices |
| `CAP_NET_RAW` | ICMP ping for connectivity verification |
| `--device=/dev/net/tun` | Access to the TUN/TAP kernel interface |
| `--security-opt label=disable` | Allow TUN access under SELinux (Fedora/RHEL) |

### Environment Variables

The entrypoint script supports these environment variables:

| Variable | Default | Description |
|---|---|---|
| `PRRR_MODE` | `server` | Container mode: `server` or `client` |
| `PRRR_LISTEN_ADDR` | `0.0.0.0:443` | Server listen address |
| `PRRR_CLIENT_NAME` | `test-client` | Client name for registration |
| `PRRR_SERVER_NAME` | `localhost` | TLS SNI server name |
| `PRRR_SERVER_ENDPOINT` | `127.0.0.1:443` | Server address for client connection |
| `PRRR_SHARED_DIR` | `/shared` | Shared volume for config exchange |
| `PRRR_TRANSPORT` | `harp` | Client transport protocol: `harp` or `masque` |

### Manual Testing

Run individual components for debugging:

```bash
# Build image
podman build -t prrr-test -f deploy/client/Containerfile .

# Create network and shared volume
podman network create prrr-net
podman volume create prrr-shared

# Start server
podman run -d --name prrr-server --network prrr-net \
  --cap-add=NET_ADMIN --cap-add=NET_RAW --device=/dev/net/tun \
  --security-opt label=disable \
  -v prrr-shared:/shared \
  -e PRRR_MODE=server \
  -e PRRR_CLIENT_NAME=test-client \
  prrr-test

# Check server logs
podman logs -f prrr-server

# Get server IP
SERVER_IP=$(podman inspect prrr-server \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

# Start client
podman run -d --name prrr-client --network prrr-net \
  --cap-add=NET_ADMIN --cap-add=NET_RAW --device=/dev/net/tun \
  --security-opt label=disable \
  -v prrr-shared:/shared:ro \
  -e PRRR_MODE=client \
  -e PRRR_SERVER_NAME=localhost \
  -e PRRR_SERVER_ENDPOINT="${SERVER_IP}:443" \
  prrr-test

# Check client logs
podman logs -f prrr-client

# Test connectivity
podman exec prrr-client ping -c 3 -W 5 10.66.66.1
podman exec prrr-server ping -c 3 -W 5 10.66.66.2

# Cleanup
podman rm -f prrr-server prrr-client
podman volume rm prrr-shared
podman network rm prrr-net
```

### Integration Tests

Rust integration tests in `tests/e2e_podman.rs` validate the container artifacts (Containerfile, entrypoint, orchestration script) without requiring Podman to be installed. The full E2E test is gated behind the `podman-e2e` feature flag and `#[ignore]` attribute — it runs only via `make podman-e2e`.

```bash
# Run unit-level container artifact tests (no Podman needed)
cargo test --test e2e_podman

# Run full E2E test (requires Podman + root-capable TUN)
make podman-e2e
```

## Troubleshooting

### "Address already in use" errors

Check which process is using the port:

```bash
sudo ss -ulnp | grep 443     # VPN port
sudo ss -tlnp | grep 8443    # Admin panel (prrr)
sudo ss -tlnp | grep 9443    # Admin panel (nginx)
```

### SSL_ERROR_RX_RECORD_TOO_LONG

You're accessing the admin panel with `https://` but it's serving HTTP. This should not happen with the proper setup. Check:

1. Access `https://admin.prrr.example.com:9443` (not `http://`)
2. Verify nginx is running: `sudo systemctl status nginx`
3. Check nginx configuration: `sudo nginx -t`
4. Verify certificates exist: `sudo ls -la /etc/letsencrypt/live/prrr.example.com/`

### Connection timeout

1. Check firewall rules allow UDP 443
2. Verify server is listening: `sudo ss -ulnp | grep 443`
3. Test from client: `nc -zvu SERVER_IP 443`
4. Check logs: `sudo journalctl -u prrr -f`

### Certificate errors

**Error: "DNS problem: NXDOMAIN looking up A for prrr.example.com"**

DNS not configured or not propagated. Wait 60 seconds and retry.

**Error: "Timeout during connect (likely firewall problem)"**

Port 80 is blocked. Allow TCP port 80 for Let's Encrypt HTTP-01 validation.

### prrr won't start

Run diagnostics:

```bash
sudo /usr/local/bin/prrr server --config /etc/prrr/server.toml doctor
```

Common issues:
- Missing password hash in `[web_admin]` section
- Invalid TOML syntax (check argon2 hash has single quotes)
- Data directory not writable
- Port already in use

### Client "Unauthorized" error

The client's public key is not registered on the server. Register the client:

```bash
sudo prrr server --config /etc/prrr/server.toml client add alice
```

Export the config and transfer to the client (see [Getting Started](getting-started.md)).

## Updating prrr

### Update binary

```bash
# Build new version locally
git pull origin main
cargo build --release --target x86_64-unknown-linux-musl

# Upload to server
scp target/x86_64-unknown-linux-musl/release/prrr root@SERVER_IP:/usr/local/bin/

# Restart service
ssh root@SERVER_IP 'systemctl restart prrr'
```

### Update configuration

Edit `/etc/prrr/server.toml` and restart:

```bash
sudo systemctl restart prrr
```

### Rolling back

```bash
# Keep old binary as backup
sudo cp /usr/local/bin/prrr /usr/local/bin/prrr.backup

# Restore if needed
sudo cp /usr/local/bin/prrr.backup /usr/local/bin/prrr
sudo systemctl restart prrr
```

## Scaling

### Multiple Servers (Load Balancing)

Use DNS round-robin or a load balancer:

```bash
# Add multiple A records
doctl compute domain records create prrr.example.com \
  --record-type A --record-name @ --record-data SERVER1_IP --record-ttl 60

doctl compute domain records create prrr.example.com \
  --record-type A --record-name @ --record-data SERVER2_IP --record-ttl 60
```

### Shared Database

For multi-server deployments, use a shared PostgreSQL database instead of SQLite:

```toml
[database]
type = "postgresql"
connection_string = "postgresql://user:pass@db.example.com/prrr"
```

## VPN Transport TLS Certificates

The VPN transport (QUIC/MASQUE) uses its own TLS certificate, separate from the nginx admin panel certificate. Using a CA-signed certificate for the VPN transport is critical for DPI resistance — self-signed certificates are easily detected by inspection systems.

### Using Let's Encrypt for VPN Transport

If you already obtained Let's Encrypt certificates (Step 4 above), point the MASQUE transport at the same certificates:

```toml
[[transports]]
name = "masque"
tls_cert = "/etc/letsencrypt/live/prrr.example.com/fullchain.pem"
tls_key = "/etc/letsencrypt/live/prrr.example.com/privkey.pem"
```

### Certificate Renewal for VPN Transport

Let's Encrypt certificates expire after 90 days. While certbot auto-renews them, prrr must reload the new certificates. Add a renewal hook to restart prrr after certificate renewal:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-prrr.sh <<'EOF'
#!/bin/bash
systemctl restart prrr
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-prrr.sh
```

### Validating TLS Configuration

Run the server doctor to verify your TLS certificate setup:

```bash
sudo prrr server --config /etc/prrr/server.toml doctor
```

The doctor checks:
- Certificate and key files exist and are readable
- PEM files parse correctly
- Certificate is not expired (warns if expiring within 30 days)
- Certificate SANs match the configured `server_name`

### Without TLS Certificates (Development Only)

When `tls_cert` and `tls_key` are not configured, the server falls back to a self-signed certificate. This is suitable for local development but should never be used in production — DPI systems flag self-signed QUIC connections.

Clients connecting to a server with a self-signed certificate must use the `--insecure` flag:

```bash
sudo $(which prrr) client --config client.toml --insecure
```

Or in the client config:

```toml
[transport]
insecure_skip_verify = true
```

**WARNING:** `--insecure` disables TLS certificate verification entirely. This makes connections vulnerable to man-in-the-middle attacks. Use only for development and testing.

## DPI Evasion Checklist

Use this checklist to verify your production deployment is resistant to Deep Packet Inspection. Run `prrr server doctor` and `prrr client doctor` to automate several of these checks.

### Server Configuration

- [ ] **Use a real domain name** — Register a domain and point it at your server. Bare IP addresses in TLS SNI are flagged by DPI.
- [ ] **Use a CA-signed TLS certificate** — Configure `tls_cert` and `tls_key` in the MASQUE `[[transports]]` entry with Let's Encrypt or another CA. Self-signed certificates are trivially detectable.
- [ ] **Set `server_name` to the real domain** — The server's `server_name` must match the domain in your TLS certificate. Mismatches between SNI and certificate SANs are a DPI signal.
- [ ] **Use port 443** — QUIC on non-standard ports draws attention. Port 443 is expected for HTTPS/QUIC traffic.
- [ ] **Verify with server doctor** — Run `prrr server --config /etc/prrr/server.toml doctor` and resolve all warnings.

### Client Configuration

- [ ] **Set `server_name` explicitly** — The client's `server_name` (SNI) must match the server's domain. Do not use `www.google.com` or any domain that does not resolve to your server — SNI/IP mismatches are a primary DPI detection vector.
- [ ] **Do not use `--insecure` in production** — Certificate verification ensures you are connecting to the intended server, not a MITM proxy.
- [ ] **Verify with client doctor** — Run `prrr client --config client.toml doctor` and resolve all warnings.

### Infrastructure

- [ ] **Enable automatic certificate renewal** — Expired certificates cause connection failures and may trigger DPI alerts. Ensure certbot timer is active and the prrr reload hook is installed.
- [ ] **Monitor certificate expiry** — The server doctor warns when certificates expire within 30 days. Run it periodically or integrate into monitoring.

## Next Steps

- [Configuration Reference](configuration.md) - All configuration options
- [Getting Started](getting-started.md) - Client setup and usage
- [REST API Reference](api.md) - Web admin API endpoints
- [CLI Reference](cli.md) - Command-line interface
