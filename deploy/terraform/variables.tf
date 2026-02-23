# FRD: specs/frds/FRD-P012.md
# SPEC.md §5.2 — Terraform variables for prrr VPN DigitalOcean deployment

variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "server_name" {
  description = "Server name used for droplet hostname and resource naming"
  type        = string
  default     = "prrr-vpn"
}

variable "region" {
  description = "DigitalOcean region slug (e.g. fra1, nyc1, sfo3)"
  type        = string
  default     = "fra1"
}

variable "droplet_size" {
  description = "Droplet size slug (e.g. s-1vcpu-1gb for $6/month)"
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "ssh_key_ids" {
  description = "List of DigitalOcean SSH key IDs to add to the droplet"
  type        = list(number)
}

variable "admin_ip_addresses" {
  description = "IP addresses allowed to access SSH and web admin (CIDR notation)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "admin_password" {
  description = "Web admin panel password"
  type        = string
  sensitive   = true
}

variable "domain" {
  description = "Domain name for DNS A record and Let's Encrypt certificates. Required for DPI-resistant deployments — bare IP addresses and self-signed certs are detectable. Leave empty to skip DNS setup (development only)."
  type        = string
  default     = ""
}

variable "admin_subdomain" {
  description = "Subdomain for admin panel (e.g., 'admin' for admin.example.com)"
  type        = string
  default     = "admin"
}

variable "vpn_port" {
  description = "VPN listen port (TCP for HARP, UDP for MASQUE)"
  type        = number
  default     = 443
}

variable "admin_https_port" {
  description = "HTTPS admin panel port (TCP, served by nginx)"
  type        = number
  default     = 9443
}

variable "certbot_email" {
  description = "Email for Let's Encrypt certificate notifications (optional)"
  type        = string
  default     = ""
}

variable "max_clients" {
  description = "Maximum number of concurrent VPN clients"
  type        = number
  default     = 100
}

variable "dns_servers" {
  description = "DNS servers for VPN clients"
  type        = list(string)
  default     = ["1.1.1.1", "8.8.8.8"]
}

variable "environment" {
  description = "Environment tag for resource identification"
  type        = string
  default     = "production"
}
