# prrr VPN — Generic server provisioning (any Linux server via SSH)
#
# Unlike the DigitalOcean module, this provisions an existing server
# using SSH with password authentication. No cloud provider required.

terraform {
  required_version = ">= 1.0"
}

locals {
  install_args = join(" ", compact([
    "--admin-pass '${var.admin_password}'",
    "--vpn-port ${var.vpn_port}",
    "--admin-port ${var.admin_https_port}",
    "--max-clients ${var.max_clients}",
    "--transport ${var.transport}",
    "--dns ${join(",", var.dns_servers)}",
    var.domain != "" ? "--domain ${var.domain}" : "--no-certbot",
    var.certbot_email != "" ? "--certbot-email ${var.certbot_email}" : "",
  ]))
}

# ---------------------------------------------------------------------------
# Upload prrr binary (if provided)
# ---------------------------------------------------------------------------

resource "null_resource" "upload_binary" {
  count = var.prrr_binary_path != "" ? 1 : 0

  connection {
    type     = "ssh"
    host     = var.server_ip
    user     = var.ssh_user
    password = var.server_password
    port     = var.ssh_port
    timeout  = "2m"
  }

  provisioner "file" {
    source      = var.prrr_binary_path
    destination = "/usr/local/bin/prrr"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /usr/local/bin/prrr",
    ]
  }
}

# ---------------------------------------------------------------------------
# Upload and run install script
# ---------------------------------------------------------------------------

resource "null_resource" "install_prrr" {
  depends_on = [null_resource.upload_binary]

  connection {
    type     = "ssh"
    host     = var.server_ip
    user     = var.ssh_user
    password = var.server_password
    port     = var.ssh_port
    timeout  = "10m"
  }

  provisioner "file" {
    source      = "${path.module}/../scripts/install-server.sh"
    destination = "/tmp/install_prrr.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/install_prrr.sh",
      "bash /tmp/install_prrr.sh ${local.install_args}",
      "rm -f /tmp/install_prrr.sh",
    ]
  }

  triggers = {
    # Re-provision when config changes
    transport      = var.transport
    admin_password = var.admin_password
    vpn_port       = var.vpn_port
    max_clients    = var.max_clients
    domain         = var.domain
  }
}

# ---------------------------------------------------------------------------
# Configure firewall
# ---------------------------------------------------------------------------

resource "null_resource" "firewall" {
  depends_on = [null_resource.install_prrr]

  connection {
    type     = "ssh"
    host     = var.server_ip
    user     = var.ssh_user
    password = var.server_password
    port     = var.ssh_port
    timeout  = "2m"
  }

  provisioner "remote-exec" {
    inline = [
      "if command -v ufw &>/dev/null; then",
      "  ufw --force enable",
      "  ufw allow ${var.ssh_port}/tcp comment 'SSH'",
      "  ufw allow 80/tcp comment 'Let\\'s Encrypt'",
      "  ufw allow ${var.admin_https_port}/tcp comment 'prrr Admin'",
      var.transport == "masque" || var.transport == "both" ? "  ufw allow ${var.vpn_port}/udp comment 'prrr MASQUE'" : "  true",
      var.transport == "harp" || var.transport == "both" ? "  ufw allow ${var.vpn_port}/tcp comment 'prrr HARP'" : "  true",
      "fi",
    ]
  }
}
