# FRD: specs/frds/FRD-P012.md
# SPEC.md §5 — prrr VPN DigitalOcean Terraform Module
#
# Resources:
#   - digitalocean_droplet.prrr_vpn     — Ubuntu 22.04 server
#   - digitalocean_firewall.prrr_vpn    — SSH + VPN + web admin rules
#   - digitalocean_domain.prrr_vpn      — DNS zone (conditional)
#   - digitalocean_record.prrr_vpn_a    — A record (conditional)

terraform {
  required_version = ">= 1.0"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

provider "digitalocean" {
  token = var.do_token
}

# ---------------------------------------------------------------------------
# Droplet
# ---------------------------------------------------------------------------

resource "digitalocean_droplet" "prrr_vpn" {
  name     = var.server_name
  image    = "ubuntu-22-04-x64"
  region   = var.region
  size     = var.droplet_size
  ssh_keys = var.ssh_key_ids

  user_data = templatefile("${path.module}/templates/cloud-init.yml", {
    admin_password = var.admin_password
    domain         = var.domain
    admin_domain   = var.admin_subdomain != "" ? "${var.admin_subdomain}.${var.domain}" : "admin.${var.domain}"
    vpn_port       = var.vpn_port
    admin_port     = var.admin_https_port
    max_clients    = var.max_clients
    dns_servers    = join(",", var.dns_servers)
    certbot_email  = var.certbot_email
  })

  tags = ["prrr-vpn", var.environment]
}

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------

resource "digitalocean_firewall" "prrr_vpn" {
  name        = "${var.server_name}-fw"
  droplet_ids = [digitalocean_droplet.prrr_vpn.id]

  # SSH — restricted to admin IPs
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.admin_ip_addresses
  }

  # VPN — open to all (HARP over TCP 443, MASQUE/QUIC over UDP 443)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "udp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Let's Encrypt HTTP-01 validation
  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Web Admin HTTPS — restricted to admin IPs
  inbound_rule {
    protocol         = "tcp"
    port_range       = var.admin_https_port
    source_addresses = var.admin_ip_addresses
  }

  # Outbound — allow all TCP
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Outbound — allow all UDP
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Outbound — allow ICMP
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# ---------------------------------------------------------------------------
# DNS (conditional — only when domain is provided)
# ---------------------------------------------------------------------------

resource "digitalocean_domain" "prrr_vpn" {
  count = var.domain != "" ? 1 : 0
  name  = var.domain
}

resource "digitalocean_record" "prrr_vpn_a" {
  count  = var.domain != "" ? 1 : 0
  domain = digitalocean_domain.prrr_vpn[0].id
  type   = "A"
  name   = "@"
  value  = digitalocean_droplet.prrr_vpn.ipv4_address
  ttl    = 300
}

resource "digitalocean_record" "prrr_admin_a" {
  count  = var.domain != "" ? 1 : 0
  domain = digitalocean_domain.prrr_vpn[0].id
  type   = "A"
  name   = var.admin_subdomain != "" ? var.admin_subdomain : "admin"
  value  = digitalocean_droplet.prrr_vpn.ipv4_address
  ttl    = 300
}
