# prrr VPN — Generic server provisioning variables
# Works with any Linux server accessible via SSH (Ubuntu 22.04+, Debian 11+, Fedora 38+)

variable "server_ip" {
  description = "IP address of the target server"
  type        = string
}

variable "server_password" {
  description = "Root password for SSH authentication"
  type        = string
  sensitive   = true
}

variable "ssh_user" {
  description = "SSH user for provisioning"
  type        = string
  default     = "root"
}

variable "ssh_port" {
  description = "SSH port"
  type        = number
  default     = 22
}

variable "transport" {
  description = "VPN transport protocol: masque (QUIC/UDP, default) or harp (HTTPS/TCP)"
  type        = string
  default     = "masque"

  validation {
    condition     = contains(["masque", "harp", "both"], var.transport)
    error_message = "Transport must be 'masque', 'harp', or 'both'."
  }
}

variable "admin_password" {
  description = "Web admin panel password"
  type        = string
  sensitive   = true
}

variable "domain" {
  description = "Domain name for TLS certificates (optional, self-signed if empty)"
  type        = string
  default     = ""
}

variable "admin_subdomain" {
  description = "Subdomain for admin panel (e.g., 'admin' for admin.example.com)"
  type        = string
  default     = "admin"
}

variable "vpn_port" {
  description = "VPN listen port (UDP for MASQUE, TCP for HARP)"
  type        = number
  default     = 443
}

variable "admin_https_port" {
  description = "HTTPS admin panel port"
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

variable "prrr_binary_path" {
  description = "Path to prebuilt prrr binary. If empty, will attempt to build on server."
  type        = string
  default     = ""
}
