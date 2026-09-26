// FRD: specs/frds/FRD-P011.md
//! Integration tests for installation scripts (P-011).
//!
//! Validates that the server and client installation scripts exist,
//! are executable, and contain all required sections per SPEC.md §1 and §2.1.

use std::{fs, path::Path};

/// Path to the server installation script.
const SERVER_SCRIPT: &str = "scripts/install-server.sh";

/// Path to the client installation script.
const CLIENT_SCRIPT: &str = "scripts/install-client.sh";

/// Load script content, panicking with a clear message if the file is missing.
fn read_script(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("Failed to read {path}: {e}"))
}

// ---------------------------------------------------------------------------
// AC-1, AC-2: Scripts exist and are executable
// ---------------------------------------------------------------------------

#[test]
fn script_server_exists() {
    let path = Path::new(SERVER_SCRIPT);
    assert!(path.exists(), "Server script missing: {SERVER_SCRIPT}");
    assert!(path.is_file(), "Server script is not a file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(path).expect("metadata").permissions();
        assert!(perms.mode() & 0o111 != 0, "Server script is not executable");
    }
}

#[test]
fn script_client_exists() {
    let path = Path::new(CLIENT_SCRIPT);
    assert!(path.exists(), "Client script missing: {CLIENT_SCRIPT}");
    assert!(path.is_file(), "Client script is not a file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(path).expect("metadata").permissions();
        assert!(perms.mode() & 0o111 != 0, "Client script is not executable");
    }
}

// ---------------------------------------------------------------------------
// AC-3, AC-4: Scripts have proper bash shebang and strict mode
// ---------------------------------------------------------------------------

#[test]
fn script_server_strict_mode() {
    let content = read_script(SERVER_SCRIPT);
    assert!(
        content.starts_with("#!/usr/bin/env bash"),
        "Server script must start with #!/usr/bin/env bash"
    );
    assert!(
        content.contains("set -euo pipefail"),
        "Server script must use strict mode (set -euo pipefail)"
    );
}

#[test]
fn script_client_strict_mode() {
    let content = read_script(CLIENT_SCRIPT);
    assert!(
        content.starts_with("#!/usr/bin/env bash"),
        "Client script must start with #!/usr/bin/env bash"
    );
    assert!(
        content.contains("set -euo pipefail"),
        "Client script must use strict mode (set -euo pipefail)"
    );
}

// ---------------------------------------------------------------------------
// AC-5: Server script OS detection (Ubuntu/Debian/Fedora)
// ---------------------------------------------------------------------------

#[test]
fn script_server_os_detection() {
    let content = read_script(SERVER_SCRIPT);
    assert!(content.contains("ubuntu"), "Server script must detect Ubuntu");
    assert!(content.contains("debian"), "Server script must detect Debian");
    assert!(content.contains("fedora"), "Server script must detect Fedora");
    assert!(content.contains("/etc/os-release"), "Server script must read /etc/os-release");
}

// ---------------------------------------------------------------------------
// AC-6: Server script architecture detection
// ---------------------------------------------------------------------------

#[test]
fn script_server_arch_detection() {
    let content = read_script(SERVER_SCRIPT);
    assert!(content.contains("uname -m"), "Server script must detect architecture via uname -m");
    assert!(content.contains("x86_64"), "Server script must support x86_64");
    assert!(content.contains("aarch64"), "Server script must support aarch64");
}

// ---------------------------------------------------------------------------
// AC-7: Server script root privilege check
// ---------------------------------------------------------------------------

#[test]
fn script_server_root_check() {
    let content = read_script(SERVER_SCRIPT);
    assert!(
        content.contains("EUID") || content.contains("id -u"),
        "Server script must check for root privileges"
    );
}

// ---------------------------------------------------------------------------
// AC-8: Server script dependency installation (apt + dnf)
// ---------------------------------------------------------------------------

#[test]
fn script_server_deps() {
    let content = read_script(SERVER_SCRIPT);
    assert!(content.contains("apt-get"), "Server script must install deps via apt-get");
    assert!(content.contains("dnf install"), "Server script must install deps via dnf");
}

// ---------------------------------------------------------------------------
// AC-9: Server script systemd service
// ---------------------------------------------------------------------------

#[test]
fn script_server_systemd() {
    let content = read_script(SERVER_SCRIPT);
    assert!(content.contains("[Unit]"), "Server script must generate systemd [Unit] section");
    assert!(
        content.contains("[Service]"),
        "Server script must generate systemd [Service] section"
    );
    assert!(
        content.contains("[Install]"),
        "Server script must generate systemd [Install] section"
    );
    assert!(content.contains("systemctl daemon-reload"), "Server script must reload systemd");
    assert!(content.contains("systemctl enable"), "Server script must enable service");
}

// ---------------------------------------------------------------------------
// AC-10: Server script UFW firewall
// ---------------------------------------------------------------------------

#[test]
fn script_server_ufw() {
    let content = read_script(SERVER_SCRIPT);
    assert!(content.contains("ufw allow"), "Server script must configure UFW rules");
    assert!(content.contains("ufw --force enable"), "Server script must enable UFW");
    assert!(content.contains("22/tcp"), "Server script must allow SSH (prevent lockout)");
}

// ---------------------------------------------------------------------------
// AC-11: Server script firewalld
// ---------------------------------------------------------------------------

#[test]
fn script_server_firewalld() {
    let content = read_script(SERVER_SCRIPT);
    assert!(content.contains("firewall-cmd"), "Server script must configure firewalld");
    assert!(content.contains("--add-masquerade"), "Server script must enable masquerading");
}

// ---------------------------------------------------------------------------
// AC-12: Server script generates server.toml config
// ---------------------------------------------------------------------------

#[test]
fn script_server_config() {
    let content = read_script(SERVER_SCRIPT);
    assert!(content.contains("server.toml"), "Server script must generate server.toml");
    assert!(content.contains("[server]"), "Server script config must have [server] section");
    assert!(content.contains("[network]"), "Server script config must have [network] section");
    assert!(content.contains("[crypto]"), "Server script config must have [crypto] section");
    assert!(
        content.contains("[[transports]]"),
        "Server script config must have [[transports]] section"
    );
    assert!(
        content.contains("[obfuscation]"),
        "Server script config must have [obfuscation] section"
    );
}

// ---------------------------------------------------------------------------
// AC-13: Server script CLI options (SPEC.md §1.1)
// ---------------------------------------------------------------------------

#[test]
fn script_server_cli_options() {
    let content = read_script(SERVER_SCRIPT);
    let required_options = [
        "--admin-pass",
        "--port",
        "--web-port",
        "--domain",
        "--no-web",
        "--dns",
        "--max-clients",
        "--data-dir",
        "--log-level",
    ];
    for opt in required_options {
        assert!(content.contains(opt), "Server script must support {opt} option");
    }
}

// ---------------------------------------------------------------------------
// AC-14: Server script IP forwarding
// ---------------------------------------------------------------------------

#[test]
fn script_server_ip_forward() {
    let content = read_script(SERVER_SCRIPT);
    assert!(content.contains("ip_forward"), "Server script must enable IP forwarding");
    assert!(content.contains("sysctl"), "Server script must apply sysctl settings");
}

// ---------------------------------------------------------------------------
// AC-15: Server script formatted success output (SPEC.md §1.6)
// ---------------------------------------------------------------------------

#[test]
fn script_server_output_format() {
    let content = read_script(SERVER_SCRIPT);
    assert!(
        content.contains("Installation Complete"),
        "Server script must show installation complete message"
    );
    assert!(content.contains("Next Steps"), "Server script must show next steps");
    assert!(content.contains("Web Admin"), "Server script must show web admin details");
}

// ---------------------------------------------------------------------------
// AC-16: Client script OS detection
// ---------------------------------------------------------------------------

#[test]
fn script_client_os_detection() {
    let content = read_script(CLIENT_SCRIPT);
    assert!(content.contains("ubuntu"), "Client script must detect Ubuntu");
    assert!(content.contains("debian"), "Client script must detect Debian");
    assert!(content.contains("fedora"), "Client script must detect Fedora");
    assert!(content.contains("/etc/os-release"), "Client script must read /etc/os-release");
}

// ---------------------------------------------------------------------------
// AC-17: Client script creates user directories
// ---------------------------------------------------------------------------

#[test]
fn script_client_dirs() {
    let content = read_script(CLIENT_SCRIPT);
    assert!(content.contains(".config/prrr"), "Client script must create config directory");
    assert!(content.contains(".local/share/prrr"), "Client script must create data directory");
    assert!(content.contains("chmod 700"), "Client script must set restrictive permissions");
}

// ---------------------------------------------------------------------------
// AC-18: Client script formatted output
// ---------------------------------------------------------------------------

#[test]
fn script_client_output_format() {
    let content = read_script(CLIENT_SCRIPT);
    assert!(
        content.contains("Installation Complete"),
        "Client script must show installation complete message"
    );
    assert!(content.contains("Next Steps"), "Client script must show next steps");
    assert!(content.contains("prrr client import"), "Client script must mention import command");
}

// ---------------------------------------------------------------------------
// AC-19: Server systemd service security hardening (SPEC.md §1.4)
// ---------------------------------------------------------------------------

#[test]
fn script_server_systemd_security() {
    let content = read_script(SERVER_SCRIPT);
    assert!(
        content.contains("NoNewPrivileges=true"),
        "Systemd service must have NoNewPrivileges"
    );
    assert!(content.contains("PrivateTmp=true"), "Systemd service must have PrivateTmp");
    assert!(
        content.contains("ProtectSystem=strict"),
        "Systemd service must have ProtectSystem=strict"
    );
    assert!(content.contains("ProtectHome=true"), "Systemd service must have ProtectHome");
    assert!(
        content.contains("CAP_NET_BIND_SERVICE"),
        "Systemd service must have CAP_NET_BIND_SERVICE"
    );
    assert!(content.contains("CAP_NET_ADMIN"), "Systemd service must have CAP_NET_ADMIN");
    assert!(
        content.contains("LimitNOFILE=65536"),
        "Systemd service must set file descriptor limit"
    );
}

// ---------------------------------------------------------------------------
// Additional structural tests
// ---------------------------------------------------------------------------

#[test]
fn script_server_admin_password_generation() {
    let content = read_script(SERVER_SCRIPT);
    assert!(
        content.contains("/dev/urandom"),
        "Server script must generate password from /dev/urandom"
    );
    assert!(
        content.contains("admin_credentials.txt"),
        "Server script must save credentials to file"
    );
    assert!(content.contains("chmod 600"), "Server script must set credentials file to 0600");
}

#[test]
fn script_server_binary_download() {
    let content = read_script(SERVER_SCRIPT);
    assert!(content.contains("curl"), "Server script must use curl for download");
    assert!(content.contains("cargo install"), "Server script must have cargo install fallback");
}

#[test]
fn script_client_binary_download() {
    let content = read_script(CLIENT_SCRIPT);
    assert!(content.contains("curl"), "Client script must use curl for download");
    assert!(content.contains("cargo install"), "Client script must have cargo install fallback");
}

#[test]
fn script_server_has_help_flag() {
    let content = read_script(SERVER_SCRIPT);
    assert!(content.contains("--help"), "Server script must support --help flag");
    assert!(content.contains("usage"), "Server script must have usage function");
}

/// Install scripts must use the same default MTU as the code.
/// If the code default changes but scripts aren't updated, every new
/// server deployment gets a stale MTU that causes QUIC datagram drops.
#[test]
fn install_scripts_use_correct_default_mtu() {
    let expected = format!("mtu = {}", prrr::config::DEFAULT_MTU);

    let server_script = read_script(SERVER_SCRIPT);
    assert!(
        server_script.contains(&expected),
        "scripts/install-server.sh must contain '{expected}'"
    );

    let deploy_script = read_script("deploy/scripts/install-server.sh");
    assert!(
        deploy_script.contains(&expected),
        "deploy/scripts/install-server.sh must contain '{expected}'"
    );

    let entrypoint = read_script("deploy/client/entrypoint.sh");
    assert!(
        entrypoint.contains(&expected),
        "deploy/client/entrypoint.sh must contain '{expected}'"
    );
}
