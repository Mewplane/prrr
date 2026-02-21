# FRD: specs/frds/FRD-P012.md
# SPEC.md §5.2 — Terraform outputs for prrr VPN deployment

output "server_ip" {
  description = "Public IPv4 address of the prrr VPN server"
  value       = digitalocean_droplet.prrr_vpn.ipv4_address
}

output "web_admin_url" {
  description = "Web admin panel URL"
  value       = "http://${digitalocean_droplet.prrr_vpn.ipv4_address}:8443"
}

output "vpn_endpoint" {
  description = "VPN endpoint for client configuration"
  value       = var.domain != "" ? "${var.domain}:443" : "${digitalocean_droplet.prrr_vpn.ipv4_address}:443"
}
