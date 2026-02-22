# FRD: specs/frds/FRD-P012.md
# SPEC.md §5.2 — Terraform outputs for prrr VPN deployment

output "server_ip" {
  description = "Public IPv4 address of the prrr VPN server"
  value       = digitalocean_droplet.prrr_vpn.ipv4_address
}

output "web_admin_url" {
  description = "HTTPS admin panel URL"
  value       = var.domain != "" ? "https://${var.admin_subdomain}.${var.domain}:${var.admin_https_port}" : "https://${digitalocean_droplet.prrr_vpn.ipv4_address}:${var.admin_https_port}"
}

output "vpn_endpoint" {
  description = "VPN endpoint for client configuration"
  value       = var.domain != "" ? "${var.domain}:${var.vpn_port}" : "${digitalocean_droplet.prrr_vpn.ipv4_address}:${var.vpn_port}"
}

output "admin_credentials" {
  description = "Default admin credentials (change immediately after first login)"
  value = {
    username = "admin"
    password = var.admin_password
  }
  sensitive = true
}

output "dns_records" {
  description = "DNS records that were created"
  value = var.domain != "" ? {
    root_domain  = "${var.domain} → ${digitalocean_droplet.prrr_vpn.ipv4_address}"
    admin_domain = "${var.admin_subdomain}.${var.domain} → ${digitalocean_droplet.prrr_vpn.ipv4_address}"
  } : {}
}

output "server_doctor_command" {
  description = "Run this command on the server to validate TLS and DPI evasion configuration"
  value       = "ssh root@${digitalocean_droplet.prrr_vpn.ipv4_address} 'prrr server --config /etc/prrr/server.toml doctor'"
}
