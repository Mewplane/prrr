# prrr VPN — Generic server outputs

output "server_ip" {
  description = "Server IP address"
  value       = var.server_ip
}

output "vpn_endpoint" {
  description = "VPN endpoint for client configuration"
  value       = var.domain != "" ? "${var.domain}:${var.vpn_port}" : "${var.server_ip}:${var.vpn_port}"
}

output "vpn_transport" {
  description = "Active VPN transport protocol"
  value       = var.transport
}

output "web_admin_url" {
  description = "HTTPS admin panel URL"
  value       = var.domain != "" ? "https://${var.admin_subdomain}.${var.domain}:${var.admin_https_port}" : "https://${var.server_ip}:${var.admin_https_port}"
}

output "admin_credentials" {
  description = "Admin panel credentials"
  value = {
    username = "admin"
    password = var.admin_password
  }
  sensitive = true
}

output "ssh_command" {
  description = "SSH command to connect to the server"
  value       = "ssh ${var.ssh_user}@${var.server_ip} -p ${var.ssh_port}"
}

output "doctor_command" {
  description = "Run on server to validate configuration"
  value       = "ssh ${var.ssh_user}@${var.server_ip} -p ${var.ssh_port} 'prrr server --config /etc/prrr/server.toml doctor'"
}
