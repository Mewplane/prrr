# prrr VPN — Terraform Deployment Module

Automated DigitalOcean deployment for prrr VPN server using Terraform.

Provisions a droplet, configures firewall rules, and optionally sets up DNS.

**Note:** There is no published prrr release binary yet. After Terraform creates
the droplet, you must upload a locally-built static binary and configure the
server manually. See the post-deployment steps below.

## Prerequisites

- [Terraform](https://www.terraform.io/downloads) >= 1.0
- A [DigitalOcean](https://www.digitalocean.com/) account and API token
- An SSH key registered with DigitalOcean
- Rust 1.85+ with musl target for cross-compilation

## Quick Start

1. Edit `terraform.tfvars` with your values:

```hcl
do_token       = "dop_v1_your_token_here"
ssh_key_ids    = [12345678]
admin_password = "your-secure-admin-password"
```

The `ssh_key_ids` value must be a list (wrapped in brackets). Find your SSH key
ID with `doctl compute ssh-key list` or from the DigitalOcean dashboard.

2. Initialize and deploy:

```bash
terraform init
terraform plan
terraform apply
```

3. Retrieve outputs:

```bash
terraform output server_ip
terraform output web_admin_url
terraform output vpn_endpoint
```

## Variables

| Name | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `do_token` | string | — | yes | DigitalOcean API token (sensitive) |
| `server_name` | string | `"prrr-vpn"` | no | Droplet hostname |
| `region` | string | `"fra1"` | no | DigitalOcean region |
| `droplet_size` | string | `"s-1vcpu-1gb"` | no | Droplet size ($6/month) |
| `ssh_key_ids` | list(number) | — | yes | SSH key IDs |
| `admin_ip_addresses` | list(string) | `["0.0.0.0/0"]` | no | Admin access CIDRs |
| `admin_password` | string | — | yes | Web admin password (sensitive) |
| `domain` | string | `""` | no | Domain for DNS A record |
| `max_clients` | number | `100` | no | Max concurrent clients |
| `dns_servers` | list(string) | `["1.1.1.1", "8.8.8.8"]` | no | Client DNS servers |
| `environment` | string | `"production"` | no | Environment tag |

## Outputs

| Name | Description |
|------|-------------|
| `server_ip` | Server public IPv4 address |
| `web_admin_url` | Web admin panel URL (http://ip:8443) |
| `vpn_endpoint` | VPN endpoint (domain:443 or ip:443) |

## Examples

### Minimal deployment

```hcl
do_token       = "dop_v1_abc123"
ssh_key_ids    = [12345678]
admin_password = "my-secure-password"
```

### With custom domain and restricted admin access

```hcl
do_token           = "dop_v1_abc123"
ssh_key_ids        = [12345678]
admin_password     = "my-secure-password"
domain             = "vpn.example.com"
admin_ip_addresses = ["203.0.113.0/24"]
region             = "nyc1"
droplet_size       = "s-2vcpu-2gb"
max_clients        = 50
environment        = "staging"
```

## Post-Deployment: Upload Binary and Configure

After `terraform apply`, the droplet exists but prrr is not yet installed
(there is no published release binary). Follow these steps:

```bash
# 1. Build a static binary locally (requires musl toolchain)
#    Fedora: sudo dnf install -y musl-gcc
#    Ubuntu: sudo apt-get install -y musl-tools
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# 2. Upload to the droplet
SERVER_IP=$(terraform output -raw server_ip)
scp target/x86_64-unknown-linux-musl/release/prrr root@$SERVER_IP:/usr/local/bin/

# 3. Configure the server (see docs/getting-started.md "Manual Server Setup on a Remote Host")
ssh root@$SERVER_IP
```

On the droplet, create the config, systemd service, and start the server.
See the [Getting Started guide](../../docs/getting-started.md#manual-server-setup-on-a-remote-host)
for full instructions.

## Cleanup

Destroy all created resources:

```bash
terraform destroy
```

## Resources Created

- **Droplet** — Ubuntu 22.04 server running prrr VPN
- **Firewall** — SSH (22/tcp), VPN (443/udp), Web Admin (8443/tcp)
- **Domain** — DNS zone (only if `domain` is set)
- **A Record** — Points domain to droplet IP (only if `domain` is set)

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  DigitalOcean                     │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  Firewall                                  │  │
│  │  ┌──────┐  ┌──────────┐  ┌──────────────┐ │  │
│  │  │SSH:22│  │VPN:443/udp│  │Web Admin:8443│ │  │
│  │  └──┬───┘  └────┬─────┘  └──────┬───────┘ │  │
│  └─────┼───────────┼───────────────┼──────────┘  │
│        │           │               │              │
│  ┌─────▼───────────▼───────────────▼──────────┐  │
│  │  Droplet: prrr-vpn                         │  │
│  │  Ubuntu 22.04 + prrr VPN server            │  │
│  │  cloud-init → install-server.sh            │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  DNS (optional)                            │  │
│  │  vpn.example.com → droplet IP              │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```
