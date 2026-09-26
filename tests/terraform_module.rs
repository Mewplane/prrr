// FRD: specs/frds/FRD-P012.md
//! Integration tests for Terraform module (P-012).
//!
//! Validates that the Terraform files exist and contain all required
//! resources, variables, and outputs per SPEC.md §5.
//!
//! QUARANTINE: The DigitalOcean-specific assertions in this file encode a
//! superseded design. Commit `97c0421` replaced `deploy/terraform/` with a
//! vendor-neutral SSH-based module (see the `main.tf` header). The DO-specific
//! tests are quarantined with `#[ignore = "BUG-stale-terraform-do-tests: ..."]`
//! pending a maintainer decision; see `specs/bugs/BUG-stale-terraform-do-tests.md`.
//! Tests that still validate the current generic module are left active.

use std::{fs, path::Path};

/// Base path for the Terraform module.
const TF_DIR: &str = "deploy/terraform";

/// Path to main.tf.
const MAIN_TF: &str = "deploy/terraform/main.tf";

/// Path to variables.tf.
const VARIABLES_TF: &str = "deploy/terraform/variables.tf";

/// Path to outputs.tf.
const OUTPUTS_TF: &str = "deploy/terraform/outputs.tf";

/// Path to cloud-init template.
const CLOUD_INIT: &str = "deploy/terraform/templates/cloud-init.yml";

/// Path to README.
const README: &str = "deploy/terraform/README.md";

/// Load file content, panicking with a clear message if missing.
fn read_tf(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("Failed to read {path}: {e}"))
}

// ---------------------------------------------------------------------------
// File existence
// ---------------------------------------------------------------------------

#[test]
fn terraform_main_exists() {
    assert!(Path::new(MAIN_TF).is_file(), "main.tf missing");
}

#[test]
fn terraform_variables_exists() {
    assert!(Path::new(VARIABLES_TF).is_file(), "variables.tf missing");
}

#[test]
fn terraform_outputs_exists() {
    assert!(Path::new(OUTPUTS_TF).is_file(), "outputs.tf missing");
}

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_cloud_init_exists() {
    assert!(Path::new(CLOUD_INIT).is_file(), "cloud-init.yml missing");
}

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_readme_exists() {
    let path = Path::new(README);
    assert!(path.is_file(), "README.md missing");
    let content = read_tf(README);
    assert!(
        content.contains("terraform init"),
        "README should contain terraform init instructions"
    );
    assert!(
        content.contains("terraform apply"),
        "README should contain terraform apply instructions"
    );
    assert!(content.contains("terraform destroy"), "README should contain cleanup instructions");
}

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_templates_dir_exists() {
    let path = Path::new(TF_DIR).join("templates");
    assert!(path.is_dir(), "templates/ directory missing");
}

// ---------------------------------------------------------------------------
// AC-1: main.tf — terraform block with version >= 1.0
// ---------------------------------------------------------------------------

#[test]
fn terraform_main_required_version() {
    let content = read_tf(MAIN_TF);
    assert!(content.contains("required_version"), "main.tf must specify required_version");
    assert!(content.contains(">= 1.0"), "main.tf must require terraform >= 1.0");
}

// ---------------------------------------------------------------------------
// AC-2: main.tf — digitalocean provider ~> 2.0
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_main_do_provider() {
    let content = read_tf(MAIN_TF);
    assert!(
        content.contains("digitalocean/digitalocean"),
        "main.tf must use digitalocean provider source"
    );
    assert!(content.contains("~> 2.0"), "main.tf must constrain provider to ~> 2.0");
}

// ---------------------------------------------------------------------------
// AC-3: main.tf — droplet resource with ubuntu-22-04-x64
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_main_droplet() {
    let content = read_tf(MAIN_TF);
    assert!(content.contains("digitalocean_droplet"), "main.tf must define a droplet resource");
    assert!(content.contains("ubuntu-22-04-x64"), "Droplet must use ubuntu-22-04-x64 image");
    assert!(content.contains("user_data"), "Droplet must include user_data for cloud-init");
    assert!(content.contains("templatefile"), "Droplet user_data must use templatefile function");
}

// ---------------------------------------------------------------------------
// AC-4: main.tf — firewall with VPN port 443/udp
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_main_firewall() {
    let content = read_tf(MAIN_TF);
    assert!(content.contains("digitalocean_firewall"), "main.tf must define a firewall resource");
    assert!(content.contains("\"443\""), "Firewall must include port 443");
    assert!(content.contains("\"udp\""), "Firewall must include UDP protocol for VPN");
}

// ---------------------------------------------------------------------------
// AC-5: main.tf — conditional DNS resources
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_main_dns() {
    let content = read_tf(MAIN_TF);
    assert!(content.contains("digitalocean_domain"), "main.tf must define a domain resource");
    assert!(content.contains("digitalocean_record"), "main.tf must define a DNS record resource");
    assert!(content.contains("var.domain"), "DNS resources must reference var.domain");
    // Conditional creation
    assert!(content.contains("count"), "DNS resources must use count for conditional creation");
}

// ---------------------------------------------------------------------------
// AC-6: variables.tf — all 11 required variables
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_variables_all_defined() {
    let content = read_tf(VARIABLES_TF);
    let required_vars = [
        "do_token",
        "server_name",
        "region",
        "droplet_size",
        "ssh_key_ids",
        "admin_ip_addresses",
        "admin_password",
        "domain",
        "max_clients",
        "dns_servers",
        "environment",
    ];
    for var in required_vars {
        let pattern = format!("variable \"{var}\"");
        assert!(content.contains(&pattern), "variables.tf must define variable \"{var}\"");
    }
}

// ---------------------------------------------------------------------------
// AC-7: variables.tf — sensitive markers
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_variables_sensitive() {
    let content = read_tf(VARIABLES_TF);
    // Count "sensitive = true" occurrences — must be at least 2 (do_token, admin_password)
    let sensitive_count = content.matches("sensitive   = true").count();
    assert!(
        sensitive_count >= 2,
        "At least do_token and admin_password must be marked sensitive (expected >= 2, got {sensitive_count})"
    );

    // Verify the sensitive variables specifically exist
    assert!(content.contains("do_token"), "variables.tf must define do_token");
    assert!(content.contains("admin_password"), "variables.tf must define admin_password");
}

// ---------------------------------------------------------------------------
// AC-8: outputs.tf — all three outputs
// ---------------------------------------------------------------------------

#[test]
fn terraform_outputs_defined() {
    let content = read_tf(OUTPUTS_TF);
    let required_outputs = ["server_ip", "web_admin_url", "vpn_endpoint"];
    for output in required_outputs {
        let pattern = format!("output \"{output}\"");
        assert!(content.contains(&pattern), "outputs.tf must define output \"{output}\"");
    }
}

// ---------------------------------------------------------------------------
// AC-9: cloud-init.yml — package_update and install script
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_cloud_init_content() {
    let content = read_tf(CLOUD_INIT);
    assert!(content.contains("#cloud-config"), "cloud-init must start with #cloud-config");
    assert!(content.contains("package_update: true"), "cloud-init must enable package_update");
    assert!(content.contains("package_upgrade: true"), "cloud-init must enable package_upgrade");
    assert!(
        content.contains("install.prrr.dev/server"),
        "cloud-init must download install script from install.prrr.dev"
    );
    assert!(content.contains("runcmd"), "cloud-init must include runcmd section");
    assert!(
        content.contains("/tmp/install_prrr.sh"),
        "cloud-init must write and execute temporary install script"
    );
}

// ---------------------------------------------------------------------------
// AC-10: cloud-init.yml — template variables
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_cloud_init_variables() {
    let content = read_tf(CLOUD_INIT);
    assert!(content.contains("${admin_password}"), "cloud-init must template admin_password");
    assert!(content.contains("${domain}"), "cloud-init must template domain");
    assert!(content.contains("${max_clients}"), "cloud-init must template max_clients");
    assert!(content.contains("${dns_servers}"), "cloud-init must template dns_servers");
}

// ---------------------------------------------------------------------------
// AC-12: Firewall — SSH restricted to admin IPs
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_firewall_ssh_restricted() {
    let content = read_tf(MAIN_TF);
    // SSH rule should reference admin_ip_addresses, not open to all
    assert!(content.contains("\"22\""), "Firewall must include SSH port 22");
    assert!(
        content.contains("var.admin_ip_addresses"),
        "SSH and web admin rules must use admin_ip_addresses variable"
    );
}

// ---------------------------------------------------------------------------
// AC-13: Firewall — VPN open to all
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_firewall_vpn_public() {
    let content = read_tf(MAIN_TF);
    // VPN rule should allow 0.0.0.0/0 and ::/0
    assert!(content.contains("0.0.0.0/0"), "VPN firewall rule must allow all IPv4");
    assert!(content.contains("::/0"), "VPN firewall rule must allow all IPv6");
}

// ---------------------------------------------------------------------------
// AC-14: Droplet — proper tags
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_droplet_tags() {
    let content = read_tf(MAIN_TF);
    assert!(content.contains("tags"), "Droplet must have tags");
    assert!(content.contains("prrr-vpn"), "Droplet must be tagged with prrr-vpn");
    assert!(content.contains("var.environment"), "Droplet must be tagged with environment");
}

// ---------------------------------------------------------------------------
// Additional structural validation
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_main_provider_block() {
    let content = read_tf(MAIN_TF);
    assert!(content.contains("provider \"digitalocean\""), "main.tf must have a provider block");
    assert!(content.contains("var.do_token"), "Provider must use var.do_token");
}

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_droplet_ssh_keys() {
    let content = read_tf(MAIN_TF);
    assert!(content.contains("ssh_keys"), "Droplet must reference ssh_keys");
    assert!(content.contains("var.ssh_key_ids"), "Droplet ssh_keys must use var.ssh_key_ids");
}

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_droplet_region() {
    let content = read_tf(MAIN_TF);
    assert!(content.contains("var.region"), "Droplet must use var.region");
    assert!(content.contains("var.droplet_size"), "Droplet must use var.droplet_size");
}

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_dns_a_record() {
    let content = read_tf(MAIN_TF);
    assert!(
        content.contains("type   = \"A\"") || content.contains("type = \"A\""),
        "DNS record must be type A"
    );
    assert!(content.contains("ttl"), "DNS record must set TTL");
    assert!(content.contains("300"), "DNS record TTL should be 300 seconds");
}

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_firewall_outbound() {
    let content = read_tf(MAIN_TF);
    assert!(content.contains("outbound_rule"), "Firewall must have outbound rules");
    assert!(content.contains("1-65535"), "Outbound rules must allow full port range");
    assert!(content.contains("icmp"), "Firewall must allow outbound ICMP");
}

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_cloud_init_cleanup() {
    let content = read_tf(CLOUD_INIT);
    assert!(content.contains("rm"), "cloud-init must clean up temporary install script");
    assert!(content.contains("final_message"), "cloud-init must include final_message");
}

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_outputs_use_droplet_ip() {
    let content = read_tf(OUTPUTS_TF);
    assert!(
        content.contains("digitalocean_droplet.prrr_vpn.ipv4_address"),
        "Outputs must reference droplet ipv4_address"
    );
}

#[test]
fn terraform_variables_have_descriptions() {
    let content = read_tf(VARIABLES_TF);
    // Every variable block should have a description
    let var_count = content.matches("variable \"").count();
    let desc_count = content.matches("description").count();
    assert_eq!(
        var_count, desc_count,
        "Every variable must have a description (found {var_count} variables but {desc_count} descriptions)"
    );
}

#[test]
fn terraform_variables_have_types() {
    let content = read_tf(VARIABLES_TF);
    let var_count = content.matches("variable \"").count();
    let type_count = content.matches("  type").count();
    assert_eq!(
        var_count, type_count,
        "Every variable must have a type (found {var_count} variables but {type_count} types)"
    );
}

#[test]
#[ignore = "BUG-stale-terraform-do-tests: stale FRD-P012 DO-specific assertions vs vendor-neutral SSH module (commit 97c0421)"]
fn terraform_cloud_init_packages() {
    let content = read_tf(CLOUD_INIT);
    assert!(content.contains("packages:"), "cloud-init must have packages section");
    assert!(content.contains("curl"), "cloud-init must install curl");
    assert!(content.contains("ufw"), "cloud-init must install ufw");
}

#[test]
fn terraform_firewall_web_admin() {
    let content = read_tf(MAIN_TF);
    assert!(
        content.contains("var.admin_https_port"),
        "Firewall must reference admin HTTPS port variable"
    );
}
