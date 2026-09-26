# Getting Started

This guide walks you through installing prrr, starting a server, registering your first client, and establishing a VPN connection.

## Prerequisites

- **Rust 1.85+** (edition 2024) for building from source
- **Linux** for production TUN device support (tests run on any platform via MockTun)
- **TCP port 443** open on the server for HARP (default transport); optionally **UDP port 443** for MASQUE
- **Root or CAP_NET_ADMIN** on the client for creating TUN devices

## Installation

### Option 1: Build from Source

```bash
git clone https://github.com/prrr-vpn/prrr.git
cd prrr
make install    # installs to ~/.cargo/bin/prrr
```

The binary is at `~/.cargo/bin/prrr`. Ensure `~/.cargo/bin` is in your PATH.

### Cross-Compilation for Remote Servers

If your server runs a different OS or glibc version (e.g., building on Fedora for Ubuntu), build a fully static binary with musl:

```bash
# Install musl toolchain (Fedora)
sudo dnf install -y musl-gcc
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl

# Upload to server
scp target/x86_64-unknown-linux-musl/release/prrr root@your-server:/usr/local/bin/
```

The musl binary is fully static and runs on any Linux distribution without glibc version dependencies.

### Option 2: Terraform (DigitalOcean)

Deploy a complete server with one command:

```bash
cd deploy/terraform
cat > terraform.tfvars <<EOF
do_token       = "dop_v1_your_token"
ssh_key_ids    = [12345678]
admin_password = "your-secure-password"
EOF

terraform init && terraform plan && terraform apply
```

After deployment, you need to upload the prrr binary manually since there is no published release binary yet:

```bash
# Build static binary locally
cargo build --release --target x86_64-unknown-linux-musl

# Upload to the droplet
SERVER_IP=$(cd deploy/terraform && terraform output -raw server_ip)
scp target/x86_64-unknown-linux-musl/release/prrr root@$SERVER_IP:/usr/local/bin/
```

Then configure the server on the droplet (see [Manual Server Setup on a Remote Host](#manual-server-setup-on-a-remote-host) below).

See [deploy/terraform/README.md](../deploy/terraform/README.md) for full Terraform details.

### Option 3: Installation Script

The server script handles binary installation, configuration generation, systemd service setup, and firewall rules.

**Server (requires root):**

```bash
curl -fsSL https://install.prrr.dev/server | sudo bash -s -- \
  --admin-pass "your-secure-password" \
  --domain vpn.example.com
```

The script supports Ubuntu 22.04+, Debian 11+, and Fedora 38+. Run with `--help` for all options:

| Option | Default | Description |
|--------|---------|-------------|
| `--admin-pass PASSWORD` | auto-generated | Web admin password |
| `--port PORT` | `443` | VPN listen port (TCP for HARP, UDP for MASQUE) |
| `--web-port PORT` | `8443` | Web admin port (TCP) |
| `--domain DOMAIN` | -- | Domain name for TLS |
| `--no-web` | `false` | Skip web admin setup |
| `--dns DNS_SERVERS` | `1.1.1.1,8.8.8.8` | Comma-separated DNS servers |
| `--max-clients N` | `100` | Maximum concurrent clients |
| `--data-dir PATH` | `/var/lib/prrr` | Data directory |
| `--log-level LEVEL` | `info` | Log level |

**Client:**

```bash
curl -fsSL https://install.prrr.dev/client | bash
```

## Server Setup

### Local Server

Create `/etc/prrr/server.toml` (or any path you prefer):

```toml
[server]
listen_addr = "0.0.0.0:443"
max_clients = 100
log_level = "info"
data_dir = "/var/lib/prrr"
server_name = "vpn.example.com"

[network]
subnet = "10.66.66.0/24"
dns_servers = ["1.1.1.1", "8.8.8.8"]
mtu = 1280

[[transports]]
name = "harp"
websocket_enabled = true
polling_enabled = true

[crypto]
identity_key_path = "/etc/prrr/keys/server_identity.key"
pq_key_path = "/etc/prrr/keys/server_pq.key"
```

All fields are optional. Missing values use built-in defaults. If `[[transports]]` is absent, the server defaults to a single HARP transport. See [Configuration Reference](configuration.md) for the complete list.

**Important:** Set `server_name` to your server's public IP or domain name. This value is used in exported client configs as the connection endpoint. If left as `localhost`, clients won't be able to connect remotely.

**TLS Certificates:** For MASQUE transport, configure `tls_cert` and `tls_key` in the `[[transports]]` entry. When set, the server presents a CA-signed certificate to clients. This is critical for production MASQUE deployments — without a real certificate, DPI systems can detect the self-signed fallback as anomalous traffic. HARP transport uses the Axum HTTP server's TLS configuration instead. See [Deployment Guide](deployment.md) for Let's Encrypt setup.

Start the server:

```bash
prrr server --config /etc/prrr/server.toml
```

On first run, the server generates identity keys (X25519 + ML-KEM-768) and saves them to the configured paths. It also creates the SQLite database for client management.

### Manual Server Setup on a Remote Host

If you uploaded the binary manually (e.g., after Terraform deployment or a plain VPS), follow these steps via SSH:

```bash
ssh root@your-server
```

**1. Create directories:**

```bash
mkdir -p /etc/prrr/keys /var/lib/prrr
```

**2. Generate an admin password hash** (for the web admin panel):

```bash
apt-get install -y argon2    # Ubuntu/Debian
SALT=$(openssl rand -base64 16)
HASH=$(echo -n "your-password" | argon2 "$SALT" -id -e)
echo "$HASH"
```

**3. Write the server config:**

Use single quotes around the `admin_password_hash` value in TOML to avoid issues with the `$` characters in the argon2 hash:

```toml
[server]
listen_addr = "0.0.0.0:443"
max_clients = 100
log_level = "info"
data_dir = "/var/lib/prrr"
server_name = "YOUR_SERVER_PUBLIC_IP"

[network]
subnet = "10.66.66.0/24"
dns_servers = ["1.1.1.1", "8.8.8.8"]
mtu = 1280

[transport]
tls_cert = "/etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem"
tls_key = "/etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem"

[crypto]
identity_key_path = "/etc/prrr/keys/server_identity.key"
pq_key_path = "/etc/prrr/keys/server_pq.key"

[web_admin]
enabled = true
listen_addr = "0.0.0.0:8443"
admin_password_hash = '$argon2id$v=19$m=4096,t=3,p=1$...'
session_timeout = 3600
```

Save to `/etc/prrr/server.toml`.

**4. Create a systemd service:**

```bash
cat > /etc/systemd/system/prrr.service <<EOF
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

[Install]
WantedBy=multi-user.target
EOF
```

**5. Enable IP forwarding, NAT, and start:**

```bash
# Enable IP forwarding (persist across reboots)
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-prrr.conf
sysctl -p /etc/sysctl.d/99-prrr.conf

# Set up NAT so VPN clients can reach the internet
iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i prrr+ -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o prrr+ -m state --state RELATED,ESTABLISHED -j ACCEPT

# Start the server
systemctl daemon-reload
systemctl enable prrr
systemctl start prrr
systemctl status prrr
```

**Note:** Replace `eth0` with your server's actual public network interface (check with `ip route show default`).

**6. Verify the server is listening:**

```bash
ss -tlnp | grep 443     # VPN — HARP (TCP)
ss -ulnp | grep 443     # VPN — MASQUE (UDP), if enabled
ss -tlnp | grep 8443    # Web admin (TCP)
```

### Run Diagnostics

Verify the server is configured correctly:

```bash
prrr server --config /etc/prrr/server.toml doctor
```

The doctor checks configuration, keys, port availability, disk space, and memory. Exit codes: 0 (all pass), 1 (warnings), 2 (failures).

## Client Setup (Step by Step)

The full client setup requires three steps: registering the client on the server, saving the private key, and importing the config.

### Step 1: Register a Client on the Server

On the server (via SSH):

```bash
prrr server --config /etc/prrr/server.toml client add alice
```

Output:

```
Client registered:
  Name:        alice
  ID:          8eef6c49-9d3f-494a-923b-360a03f2efb1
  IP Address:  10.66.66.2
  Public Key:  xFnUbC9fouZzxw51y7nnRGOAXzRzEFJTUSrKoJnMwj4=
  Private Key: YXGQV8fXw7CtpUceLM9Dz+HhKjyGBpZypIXk5UpGs6U=

Save the private key now. It will not be shown again.
```

**Copy the Private Key value immediately.** The server does not store client private keys -- this is the only time it is displayed.

### Step 2: Export the Client Config

Still on the server:

```bash
prrr server --config /etc/prrr/server.toml client export alice > /tmp/alice.toml
```

### Step 3: Transfer Config and Private Key to the Client Machine

From your local machine:

```bash
scp root@your-server:/tmp/alice.toml /tmp/alice.toml
```

### Step 4: Save the Private Key Locally

The exported config does not contain the client private key (by design -- it is sensitive material). You need to save it separately and reference it from the config:

```bash
mkdir -p ~/.local/share/prrr/keys
echo -n "YXGQV8fXw7CtpUceLM9Dz+HhKjyGBpZypIXk5UpGs6U=" | base64 -d > ~/.local/share/prrr/keys/client.key
chmod 600 ~/.local/share/prrr/keys/client.key
```

Then add the key path to the config file:

```bash
echo '' >> /tmp/alice.toml
echo "private_key_path = \"$HOME/.local/share/prrr/keys/client.key\"" >> /tmp/alice.toml
```

### Step 5: Import and Connect

```bash
prrr client import /tmp/alice.toml
```

This saves the config to `~/.config/prrr/client.toml`.

Connect:

```bash
sudo $(which prrr) client --config ~/.config/prrr/client.toml
```

**Note:** `sudo` is required to create the TUN network device. Use `$(which prrr)` because sudo may not have `~/.cargo/bin` in its PATH.

### Step 6 (Recommended): Install as a System Service

For a user-friendly experience (start/stop VPN without remembering commands), install the client as a systemd service:

```bash
cd prrr
sudo deploy/client/install-client.sh ~/.config/prrr/client.toml
```

This installs the prrr binary, routing helper, and systemd service. Now you can manage the VPN with:

```bash
sudo systemctl start prrr-client    # Connect VPN
sudo systemctl stop prrr-client     # Disconnect VPN
systemctl status prrr-client        # Check status
journalctl -u prrr-client -f        # Follow logs
```

The service automatically:
- Creates the TUN device
- Sets up DNS via systemd-resolved
- Cleans up routing and DNS on disconnect

To **route all internet traffic** through the VPN (full tunnel), add to `/etc/prrr/client.toml`:

```toml
[routing]
all_traffic = true
```

Then restart: `sudo systemctl restart prrr-client`

To route only selected services through the VPN, add their hostnames instead:

```bash
sudo $(which prrr) client --config /etc/prrr/client.toml route add chatgpt.com
sudo $(which prrr) client --config /etc/prrr/client.toml route add claude.ai
sudo $(which prrr) client --config /etc/prrr/client.toml route add youtube.com
sudo $(which prrr) client --config /etc/prrr/client.toml route add telegram.org
sudo systemctl restart prrr-client
```

Add any additional hostnames used by a service (for example, an API or media
host). See [Client routing configuration](configuration.md#selected-resource-routing)
for the IPv4 and DNS-resolution limits.

> **The service runs `/usr/local/bin/prrr`, not `~/.cargo/bin/prrr`.**
> `cargo install` / `make install` will **not** update the binary or the routing
> hook that `prrr-client.service` executes, so new config options such as
> `[routing].resources` are silently ignored. After changing the code, deploy it
> the way the service sees it:
>
> ```bash
> make install-system   # builds, then sudo-installs binary + prrr-route to /usr/local/bin
> sudo systemctl restart prrr-client
> ```

To start the VPN automatically on boot:

```bash
sudo systemctl enable prrr-client
```

### Verify Connection

On the client side, you should see (HARP, default):

```
INFO prrr::client: connecting to 164.92.235.224:443 via HARP
INFO prrr::client: HARP session established (WebSocket)
INFO prrr::client: hybrid handshake complete
INFO prrr::client: tunnel pipeline running
```

Or with MASQUE transport:

```
INFO prrr::client: connecting to 164.92.235.224:443 via MASQUE
INFO prrr::client: QUIC connection established to 164.92.235.224:443
INFO prrr::client: MASQUE tunnel established
INFO prrr::client: hybrid handshake complete
INFO prrr::client: tunnel pipeline running
```

On the server side:

```
INFO prrr::server: client connected from 203.0.113.10:40692
INFO prrr::server: client authenticated: alice (10.66.66.2)
INFO prrr::tunnel::pipeline: tunnel pipeline started
```

Disconnect with Ctrl+C.

## Quick Reference: All-in-One Client Setup

For convenience, here is the entire client setup from your local machine in one block (replace values accordingly):

```bash
# On server: register + export
ssh root@your-server 'prrr server --config /etc/prrr/server.toml client add alice'
# COPY THE PRIVATE KEY from the output above

ssh root@your-server 'prrr server --config /etc/prrr/server.toml client export alice' > /tmp/alice.toml

# Locally: save private key
mkdir -p ~/.local/share/prrr/keys
echo -n "THE_PRIVATE_KEY_BASE64" | base64 -d > ~/.local/share/prrr/keys/client.key
chmod 600 ~/.local/share/prrr/keys/client.key
echo -e "\nprivate_key_path = \"$HOME/.local/share/prrr/keys/client.key\"" >> /tmp/alice.toml

# Import and connect
prrr client import /tmp/alice.toml
sudo $(which prrr) client --config ~/.config/prrr/client.toml
```

## Managing Clients

### List Clients

```bash
prrr server --config /etc/prrr/server.toml client list
```

### Remove a Client

```bash
prrr server --config /etc/prrr/server.toml client remove alice
```

This revokes the client and releases its IP address. The client can no longer authenticate.

## Web Admin Panel

The web admin provides:
- Real-time dashboard with connection stats
- Client management (add, remove, view status)
- Config export with QR codes
- Server settings view

For production deployments, use HTTPS with Let's Encrypt (automated by the installation script). For manual setup, see the [Deployment Guide](deployment.md#https-admin-panel-with-lets-encrypt).

### Quick Start (Development Only)

For local testing without HTTPS, add to your server config:

```toml
[web_admin]
enabled = true
listen = "127.0.0.1:8443"
admin_password_hash = '$argon2id$v=19$m=4096,t=3,p=1$...'
```

Generate the password hash:

```bash
sudo apt-get install -y argon2    # Ubuntu/Debian
sudo dnf install -y argon2        # Fedora
echo -n "your-password" | argon2 $(openssl rand -base64 16) -id -t 3 -m 16 -p 1 -e
```

Access at `http://127.0.0.1:8443` (HTTP only, not suitable for remote access).

### Production Setup (HTTPS)

Use the installation script for automatic HTTPS setup:

```bash
curl -fsSL https://raw.githubusercontent.com/prrr-vpn/prrr/main/deploy/scripts/install-server.sh | sudo bash -s -- \
  --domain prrr.example.com \
  --admin-pass "your-secure-password"
```

This configures:
- Let's Encrypt certificates for your domain
- Nginx reverse proxy with TLS on port 9443
- Automatic certificate renewal
- Firewall rules (UDP 443, TCP 80, TCP 9443)

Access at `https://admin.prrr.example.com:9443` with credentials `admin` / `your-secure-password`.

For manual HTTPS setup, see the [Deployment Guide](deployment.md).

## Enabling Monitoring

Add the `[monitoring]` section for Prometheus metrics:

```toml
[monitoring]
metrics_enabled = true
prometheus_port = 9090
```

Then scrape `http://<server-ip>:9090/metrics` with Prometheus. A health endpoint is available at `http://<server-ip>:9090/health`.

## Signal Handling

prrr handles graceful shutdown on SIGINT (Ctrl+C) and SIGTERM (systemd, Docker). Active connections are closed cleanly before the process exits.

## Troubleshooting

### Server won't start

1. Run `prrr server doctor` to check configuration, keys, and port availability.
2. Check that TCP port 443 is not in use: `ss -tlnp | grep 443` (for HARP); also `ss -ulnp | grep 443` (for MASQUE).
3. Verify the data directory is writable.
4. Try `--log-level debug` for detailed output.

### "GLIBC not found" error on remote server

The binary was built on a newer Linux distribution than the server. Build a static binary with musl:

```bash
sudo dnf install -y musl-gcc              # Fedora
sudo apt-get install -y musl-tools        # Ubuntu/Debian
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The resulting binary at `target/x86_64-unknown-linux-musl/release/prrr` is fully static.

### TOML parse error with argon2 hash

If the server fails with a TOML parse error on the `admin_password_hash` field, use **single quotes** (TOML literal string) around the hash value instead of double quotes. The `$` characters in argon2 hashes can cause parsing issues with double-quoted strings:

```toml
# Correct -- single quotes (literal string)
admin_password_hash = '$argon2id$v=19$m=4096,t=3,p=1$salt$hash'

# Wrong -- double quotes may cause parse errors
admin_password_hash = "$argon2id$v=19$m=4096,t=3,p=1$salt$hash"
```

### Client says "server address required"

The client could not determine where to connect. Ensure either:
- The config file has `[server].endpoint` set (e.g., `endpoint = "vpn.example.com:443"`)
- Or pass `--server <ADDR>` on the command line

If you exported the config from a server where `server_name` was set to `localhost` or `0.0.0.0`, the endpoint in the export will be wrong. Fix the server config's `[server].server_name` to the public IP or domain, then re-export.

### Resource route does not activate (you still see your local exit IP)

Work through these checks in order:

1. **Is the running service actually resource-aware?** Run
   `grep PRRR_RESOURCE_IPS /run/prrr/env` while the tunnel is up. If the key is
   missing, the service is executing a stale `/usr/local/bin/prrr` (the
   `prrr-client.service` unit only ever runs that path). Fix with
   `make install-system && sudo systemctl restart prrr-client`.
2. **Are the routes and rules present?** `ip route show table 51820` must list
   one `/32` per resolved resource address, and `ip rule` must contain the
   `not fwmark 51820 table 51820` rule. Missing entries usually mean the
   `/usr/local/bin/prrr-route` hook is also stale — the same
   `make install-system` step updates it.
3. **Is the tunnel link up?** `ip link show prrr0` must not be `DOWN`; routes
   into a DOWN device are inert. The current hook brings it up on `up`; a
   persistent DOWN state after restart indicates a TUN creation failure in the
   service logs (`journalctl -u prrr-client`).
4. **Does the destination match a route?** `ip route get <resource-ip>` must
   show `dev prrr0`. Resource routing is IPv4-only: a browser that reaches the
   service over IPv6 bypasses the tunnel entirely — disable IPv6 on the host or
   route everything with `all_traffic = true`.

Resource routing resolves hostnames when the client starts, so DNS changes
require a client restart. URLs, wildcards, CIDRs, and IPv6-only hostnames are
not valid resource entries.

### "Unauthorized client" error

The client's public key is not registered on the server. This happens when:
- The client is using an **ephemeral keypair** instead of the registered one. Ensure the config has `private_key_path` pointing to the saved client private key (see [Step 4](#step-4-save-the-private-key-locally)).
- The client was revoked or never registered. Re-register with `prrr server client add`.

### "sudo: prrr: command not found"

`sudo` does not inherit the user's PATH, so `~/.cargo/bin/prrr` is not found. Use the full path:

```bash
sudo $(which prrr) client --config ~/.config/prrr/client.toml
# or
sudo /home/youruser/.cargo/bin/prrr client --config ...
```

### SSL_ERROR_RX_RECORD_TOO_LONG on web admin

The web admin is serving HTTP but you're accessing with HTTPS. Solutions:

1. **Recommended**: Use the installation script to set up nginx with Let's Encrypt HTTPS
2. **Development only**: Access via HTTP at `http://localhost:8443`
3. **Manual**: Follow the [HTTPS setup guide](deployment.md#https-admin-panel-with-lets-encrypt)

### Stale clients warning

Clients that haven't connected in 30+ days trigger a warning in `prrr server doctor`. Remove unused clients to free IP addresses: `prrr server client remove <name>`.

### Client Diagnostics

Check connectivity before connecting:

```bash
prrr client --config ~/.config/prrr/client.toml doctor
```

This verifies key presence, configuration validity, SNI configuration, and server reachability. The doctor will warn if `server_name` is not set or uses a suspicious value like `www.google.com`.

### TLS certificate verification errors

By default, the client verifies the server's TLS certificate against Mozilla's CA root store. If you see certificate errors during development with self-signed certificates, use the `--insecure` flag:

```bash
sudo $(which prrr) client --config ~/.config/prrr/client.toml --insecure
```

Or set in the client config file:

```toml
[transport]
insecure_skip_verify = true
```

**WARNING:** Never use `--insecure` in production. It disables TLS certificate verification, making connections vulnerable to man-in-the-middle attacks. For production, configure a CA-signed certificate on the server (see [Deployment Guide](deployment.md)).

### Missing server_name

The client requires `server_name` (TLS SNI) to be set, either via `--server-name` on the CLI or `[server].server_name` in the config file. If missing, the client exits with an error. The exported config from `prrr server client export` includes the server's configured `server_name` automatically.

## Next Steps

- [Configuration Reference](configuration.md) -- All config options with defaults
- [CLI Reference](cli.md) -- Complete command and flag reference
- [REST API Reference](api.md) -- Web admin API endpoints
- [Architecture Overview](overview.md) -- How the components fit together
