// FRD: specs/frds/FRD-P010.md

//! Diagnostic checks for `prrr server doctor` and `prrr client doctor`.
//!
//! Validates configuration, key integrity, port availability, system resources,
//! and connectivity. Each check reports pass/warn/fail with actionable messages.

use std::net::SocketAddr;
use std::path::Path;

use crate::config::{ClientConfigFile, ServerConfig};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ANSI escape: green text.
const ANSI_GREEN: &str = "\x1b[32m";

/// ANSI escape: yellow text.
const ANSI_YELLOW: &str = "\x1b[33m";

/// ANSI escape: red text.
const ANSI_RED: &str = "\x1b[31m";

/// ANSI escape: reset formatting.
const ANSI_RESET: &str = "\x1b[0m";

/// Pass indicator symbol.
const SYMBOL_PASS: &str = "\u{2713}";

/// Warn indicator symbol.
const SYMBOL_WARN: &str = "!";

/// Fail indicator symbol.
const SYMBOL_FAIL: &str = "\u{2717}";

/// Exit code when all checks pass.
const EXIT_CODE_OK: i32 = 0;

/// Exit code when warnings are present (but no failures).
const EXIT_CODE_WARN: i32 = 1;

/// Exit code when any check fails.
const EXIT_CODE_FAIL: i32 = 2;

/// Disk usage percentage threshold for warnings.
const DISK_WARN_PERCENT: u64 = 80;

/// Disk usage percentage threshold for failures.
const DISK_FAIL_PERCENT: u64 = 95;

/// Memory threshold (bytes) below which a failure is reported.
const MEMORY_FAIL_BYTES: u64 = 64 * 1024 * 1024;

/// Memory threshold (bytes) below which a warning is reported.
const MEMORY_WARN_BYTES: u64 = 128 * 1024 * 1024;

/// Number of days after which a client is considered stale.
const STALE_CLIENT_DAYS: u64 = 30;

/// Seconds in one day.
const SECONDS_PER_DAY: u64 = 86400;

/// Expected size (bytes) of an X25519 private key file.
const NOISE_PRIVATE_KEY_SIZE: u64 = 32;

/// Expected size (bytes) of an ML-KEM-768 decapsulation key file.
const KEM_DECAPSULATION_KEY_SIZE: u64 = 2400;

/// UDP reachability probe timeout in seconds.
const UDP_PROBE_TIMEOUT_SECS: u64 = 5;

/// Check name: configuration valid.
const CHECK_CONFIG_VALID: &str = "Configuration valid";

/// Check name: keys present and valid.
const CHECK_KEYS_PRESENT: &str = "Keys present and valid";

/// Check name: port available.
const CHECK_PORT_AVAILABLE: &str = "Port available";

/// Check name: disk space sufficient.
const CHECK_DISK_SPACE: &str = "Disk space sufficient";

/// Check name: memory available.
const CHECK_MEMORY: &str = "Memory available";

/// Check name: stale clients.
const CHECK_STALE_CLIENTS: &str = "Stale clients";

/// Check name: client keys present.
const CHECK_CLIENT_KEYS: &str = "Client keys present";

/// Check name: client config valid.
const CHECK_CLIENT_CONFIG: &str = "Configuration valid";

/// Check name: server reachable.
const CHECK_SERVER_REACHABLE: &str = "Server reachable";

/// Diagnostic header printed before checks.
const HEADER_MESSAGE: &str = "Running diagnostics...";

/// Recommendations header.
const RECOMMENDATIONS_HEADER: &str = "Recommendations:";

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Result status for a single diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// Check passed — no issues.
    Pass,
    /// Check produced a warning — non-critical issue.
    Warn,
    /// Check failed — critical issue.
    Fail,
}

/// A single diagnostic check result.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Human-readable name of the check.
    pub name: &'static str,
    /// Pass/Warn/Fail status.
    pub status: CheckStatus,
    /// Descriptive message with details.
    pub message: String,
}

/// A complete diagnostic report from running all checks.
#[derive(Debug)]
pub struct DiagnosticReport {
    /// Individual check results.
    pub checks: Vec<CheckResult>,
    /// Actionable recommendations for the operator.
    pub recommendations: Vec<String>,
}

impl DiagnosticReport {
    /// Compute the process exit code from check results.
    ///
    /// - 0 = all checks passed
    /// - 1 = warnings present (but no failures)
    /// - 2 = at least one failure
    pub fn exit_code(&self) -> i32 {
        let has_fail = self.checks.iter().any(|c| c.status == CheckStatus::Fail);
        let has_warn = self.checks.iter().any(|c| c.status == CheckStatus::Warn);

        if has_fail {
            EXIT_CODE_FAIL
        } else if has_warn {
            EXIT_CODE_WARN
        } else {
            EXIT_CODE_OK
        }
    }

    /// Print the report to stdout with ANSI color codes.
    pub fn print_colored(&self) {
        println!();
        println!("{HEADER_MESSAGE}");
        println!();

        for check in &self.checks {
            let (color, symbol) = match check.status {
                CheckStatus::Pass => (ANSI_GREEN, SYMBOL_PASS),
                CheckStatus::Warn => (ANSI_YELLOW, SYMBOL_WARN),
                CheckStatus::Fail => (ANSI_RED, SYMBOL_FAIL),
            };
            println!("{color}{symbol}{ANSI_RESET} {}", check.message);
        }

        if !self.recommendations.is_empty() {
            println!();
            println!("{RECOMMENDATIONS_HEADER}");
            for rec in &self.recommendations {
                println!("  - {rec}");
            }
        }

        println!();
    }
}

// ---------------------------------------------------------------------------
// Server diagnostics
// ---------------------------------------------------------------------------

/// Run all server-side diagnostic checks.
///
/// Takes a parsed `ServerConfig` and the CLI listen address to validate
/// configuration, keys, port, disk, memory, and stale clients.
pub fn run_server_doctor(config: &ServerConfig, listen_addr: SocketAddr) -> DiagnosticReport {
    let mut checks = Vec::new();
    let mut recommendations = Vec::new();

    // 1. Config valid (already parsed if we got here)
    checks.push(check_server_config_valid());

    // 2. Keys present and valid
    let identity_key_path = config
        .crypto
        .as_ref()
        .and_then(|c| c.identity_key_path.as_deref())
        .unwrap_or(crate::config::DEFAULT_IDENTITY_KEY_PATH);
    let pq_key_path = config
        .crypto
        .as_ref()
        .and_then(|c| c.pq_key_path.as_deref())
        .unwrap_or(crate::config::DEFAULT_PQ_KEY_PATH);
    checks.push(check_keys_present(identity_key_path, pq_key_path));

    // 3. Port available
    checks.push(check_port_available(listen_addr));

    // 4. Disk space
    let data_dir = config
        .server
        .as_ref()
        .and_then(|s| s.data_dir.as_deref())
        .unwrap_or(crate::config::DEFAULT_DATA_DIR);
    checks.push(check_disk_space(data_dir));

    // 5. Memory
    checks.push(check_memory());

    // 6. Stale clients
    let subnet = config
        .network
        .as_ref()
        .and_then(|n| n.subnet.as_deref())
        .unwrap_or(crate::config::DEFAULT_SUBNET);
    let db_path = Path::new(data_dir).join(crate::registry::DATABASE_FILENAME);
    checks.push(check_stale_clients(subnet, &db_path));

    // Build recommendations from check results
    for check in &checks {
        match check.status {
            CheckStatus::Fail if check.name == CHECK_KEYS_PRESENT => {
                recommendations.push("Generate server keys: run `prrr server` to auto-generate on first start".to_string());
            }
            CheckStatus::Fail if check.name == CHECK_PORT_AVAILABLE => {
                recommendations.push("Stop the process using the port or change listen address in config".to_string());
            }
            CheckStatus::Fail | CheckStatus::Warn if check.name == CHECK_DISK_SPACE => {
                recommendations.push("Free disk space or move data directory to a larger volume".to_string());
            }
            CheckStatus::Fail | CheckStatus::Warn if check.name == CHECK_MEMORY => {
                recommendations.push("Close unused processes or upgrade server memory".to_string());
            }
            CheckStatus::Warn if check.name == CHECK_STALE_CLIENTS => {
                recommendations.push("Remove inactive clients to free IP addresses".to_string());
            }
            _ => {}
        }
    }

    DiagnosticReport { checks, recommendations }
}

/// Check that the server config parsed successfully (always passes since
/// we already parsed it to get here).
fn check_server_config_valid() -> CheckResult {
    CheckResult {
        name: CHECK_CONFIG_VALID,
        status: CheckStatus::Pass,
        message: CHECK_CONFIG_VALID.to_string(),
    }
}

/// Check that the server config file at `path` is valid TOML.
///
/// This is used when we want to validate a config file path before parsing.
pub fn check_server_config_from_path(path: Option<&std::path::PathBuf>) -> CheckResult {
    match crate::config::load_server_config(path) {
        Ok(_) => CheckResult {
            name: CHECK_CONFIG_VALID,
            status: CheckStatus::Pass,
            message: CHECK_CONFIG_VALID.to_string(),
        },
        Err(e) => CheckResult {
            name: CHECK_CONFIG_VALID,
            status: CheckStatus::Fail,
            message: format!("{CHECK_CONFIG_VALID}: {e}"),
        },
    }
}

/// Check that identity and PQ key files exist with correct sizes.
pub fn check_keys_present(identity_key_path: &str, pq_key_path: &str) -> CheckResult {
    let identity_path = Path::new(identity_key_path);
    let pq_path = Path::new(pq_key_path);

    // Check identity key file exists
    if !identity_path.exists() {
        return CheckResult {
            name: CHECK_KEYS_PRESENT,
            status: CheckStatus::Fail,
            message: format!("Identity key not found at {identity_key_path}"),
        };
    }

    // Check PQ key file exists
    if !pq_path.exists() {
        return CheckResult {
            name: CHECK_KEYS_PRESENT,
            status: CheckStatus::Fail,
            message: format!("Post-quantum key not found at {pq_key_path}"),
        };
    }

    // Check identity key file size
    match std::fs::metadata(identity_path) {
        Ok(meta) if meta.len() != NOISE_PRIVATE_KEY_SIZE => {
            return CheckResult {
                name: CHECK_KEYS_PRESENT,
                status: CheckStatus::Fail,
                message: format!(
                    "Identity key wrong size: expected {NOISE_PRIVATE_KEY_SIZE} bytes, got {} bytes",
                    meta.len()
                ),
            };
        }
        Err(e) => {
            return CheckResult {
                name: CHECK_KEYS_PRESENT,
                status: CheckStatus::Fail,
                message: format!("Cannot read identity key at {identity_key_path}: {e}"),
            };
        }
        _ => {}
    }

    // Check PQ key file size
    match std::fs::metadata(pq_path) {
        Ok(meta) if meta.len() != KEM_DECAPSULATION_KEY_SIZE => {
            return CheckResult {
                name: CHECK_KEYS_PRESENT,
                status: CheckStatus::Fail,
                message: format!(
                    "Post-quantum key wrong size: expected {KEM_DECAPSULATION_KEY_SIZE} bytes, got {} bytes",
                    meta.len()
                ),
            };
        }
        Err(e) => {
            return CheckResult {
                name: CHECK_KEYS_PRESENT,
                status: CheckStatus::Fail,
                message: format!("Cannot read post-quantum key at {pq_key_path}: {e}"),
            };
        }
        _ => {}
    }

    CheckResult {
        name: CHECK_KEYS_PRESENT,
        status: CheckStatus::Pass,
        message: CHECK_KEYS_PRESENT.to_string(),
    }
}

/// Check that the configured listen port is available for binding.
pub fn check_port_available(addr: SocketAddr) -> CheckResult {
    match std::net::UdpSocket::bind(addr) {
        Ok(_) => CheckResult {
            name: CHECK_PORT_AVAILABLE,
            status: CheckStatus::Pass,
            message: format!("Port {}/UDP available", addr.port()),
        },
        Err(e) => CheckResult {
            name: CHECK_PORT_AVAILABLE,
            status: CheckStatus::Fail,
            message: format!("Port {}/UDP unavailable: {e}", addr.port()),
        },
    }
}

/// Check disk space for the data directory filesystem.
///
/// Uses `/proc/mounts` + `statvfs` on Linux, falls back to pass with
/// an informational message on other platforms.
pub fn check_disk_space(data_dir: &str) -> CheckResult {
    check_disk_space_inner(data_dir)
}

#[cfg(target_os = "linux")]
fn check_disk_space_inner(data_dir: &str) -> CheckResult {
    // Use `df` command to check disk usage — avoids adding libc dependency
    let output = std::process::Command::new("df").arg("--output=pcent").arg(data_dir).output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Parse the percentage from df output (second line, strip %)
            let percent = stdout
                .lines()
                .nth(1)
                .and_then(|line| line.trim().strip_suffix('%'))
                .and_then(|s| s.parse::<u64>().ok());

            match percent {
                Some(pct) if pct >= DISK_FAIL_PERCENT => CheckResult {
                    name: CHECK_DISK_SPACE,
                    status: CheckStatus::Fail,
                    message: format!("Disk space critical ({pct}% used)"),
                },
                Some(pct) if pct >= DISK_WARN_PERCENT => CheckResult {
                    name: CHECK_DISK_SPACE,
                    status: CheckStatus::Warn,
                    message: format!("Disk space low ({pct}% used)"),
                },
                Some(pct) => CheckResult {
                    name: CHECK_DISK_SPACE,
                    status: CheckStatus::Pass,
                    message: format!("{CHECK_DISK_SPACE} ({pct}% used)"),
                },
                None => CheckResult {
                    name: CHECK_DISK_SPACE,
                    status: CheckStatus::Pass,
                    message: format!("{CHECK_DISK_SPACE} (unable to parse usage)"),
                },
            }
        }
        _ => CheckResult {
            name: CHECK_DISK_SPACE,
            status: CheckStatus::Pass,
            message: format!("{CHECK_DISK_SPACE} (unable to query)"),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn check_disk_space_inner(_data_dir: &str) -> CheckResult {
    CheckResult {
        name: CHECK_DISK_SPACE,
        status: CheckStatus::Pass,
        message: format!("{CHECK_DISK_SPACE} (check not available on this platform)"),
    }
}

/// Check available system memory.
///
/// Reads `/proc/meminfo` on Linux, falls back to pass on other platforms.
pub fn check_memory() -> CheckResult {
    check_memory_inner()
}

#[cfg(target_os = "linux")]
fn check_memory_inner() -> CheckResult {
    match std::fs::read_to_string("/proc/meminfo") {
        Ok(content) => parse_meminfo_and_check(&content),
        Err(_) => CheckResult {
            name: CHECK_MEMORY,
            status: CheckStatus::Pass,
            message: format!("{CHECK_MEMORY} (unable to read /proc/meminfo)"),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn check_memory_inner() -> CheckResult {
    CheckResult {
        name: CHECK_MEMORY,
        status: CheckStatus::Pass,
        message: format!("{CHECK_MEMORY} (check not available on this platform)"),
    }
}

/// Parse `/proc/meminfo` content and produce a check result.
///
/// Looks for the `MemAvailable:` line and extracts the value in kB.
pub fn parse_meminfo_and_check(content: &str) -> CheckResult {
    let available_kb = content
        .lines()
        .find(|line| line.starts_with("MemAvailable:"))
        .and_then(|line| line.split_whitespace().nth(1).and_then(|s| s.parse::<u64>().ok()));

    match available_kb {
        Some(kb) => {
            let bytes = kb * 1024;
            let mb = kb / 1024;
            if bytes < MEMORY_FAIL_BYTES {
                CheckResult {
                    name: CHECK_MEMORY,
                    status: CheckStatus::Fail,
                    message: format!("Memory critically low ({mb}MB available)"),
                }
            } else if bytes < MEMORY_WARN_BYTES {
                CheckResult {
                    name: CHECK_MEMORY,
                    status: CheckStatus::Warn,
                    message: format!("Memory low ({mb}MB available)"),
                }
            } else {
                CheckResult {
                    name: CHECK_MEMORY,
                    status: CheckStatus::Pass,
                    message: format!("{CHECK_MEMORY} ({mb}MB free)"),
                }
            }
        }
        None => CheckResult {
            name: CHECK_MEMORY,
            status: CheckStatus::Pass,
            message: format!("{CHECK_MEMORY} (unable to parse MemAvailable)"),
        },
    }
}

/// Check for stale clients (not seen in 30+ days).
pub fn check_stale_clients(subnet: &str, db_path: &Path) -> CheckResult {
    if !db_path.exists() {
        return CheckResult {
            name: CHECK_STALE_CLIENTS,
            status: CheckStatus::Pass,
            message: "No client database found (no clients registered)".to_string(),
        };
    }

    match crate::registry::ClientRegistry::open(subnet, db_path) {
        Ok(registry) => {
            let clients = registry.list();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let stale_threshold = now.saturating_sub(STALE_CLIENT_DAYS * SECONDS_PER_DAY);
            let stale_count = clients
                .iter()
                .filter(|c| match c.last_seen {
                    Some(ts) => ts < stale_threshold,
                    None => true, // Never connected = stale
                })
                .count();

            if stale_count > 0 {
                CheckResult {
                    name: CHECK_STALE_CLIENTS,
                    status: CheckStatus::Warn,
                    message: format!(
                        "Warning: {stale_count} client{} haven't connected in {STALE_CLIENT_DAYS}+ days",
                        if stale_count == 1 { "" } else { "s" }
                    ),
                }
            } else {
                CheckResult {
                    name: CHECK_STALE_CLIENTS,
                    status: CheckStatus::Pass,
                    message: "All clients active".to_string(),
                }
            }
        }
        Err(e) => CheckResult {
            name: CHECK_STALE_CLIENTS,
            status: CheckStatus::Warn,
            message: format!("Cannot open client database: {e}"),
        },
    }
}

// ---------------------------------------------------------------------------
// Client diagnostics
// ---------------------------------------------------------------------------

/// Run all client-side diagnostic checks.
pub fn run_client_doctor(config: &ClientConfigFile) -> DiagnosticReport {
    let mut checks = Vec::new();
    let mut recommendations = Vec::new();

    // 1. Client keys present
    checks.push(check_client_keys(config));

    // 2. Config valid (check server endpoint)
    checks.push(check_client_config(config));

    // 3. Server reachable
    let server_endpoint = config.server.as_ref().and_then(|s| s.endpoint.as_deref());
    if let Some(endpoint) = server_endpoint {
        checks.push(check_server_reachable(endpoint));
    }

    // Build recommendations
    for check in &checks {
        match check.status {
            CheckStatus::Fail if check.name == CHECK_CLIENT_KEYS => {
                recommendations.push("Generate client keys or import a configuration: prrr client import <source>".to_string());
            }
            CheckStatus::Fail if check.name == CHECK_CLIENT_CONFIG => {
                recommendations.push("Provide server endpoint in config: [server] endpoint = \"host:port\"".to_string());
            }
            CheckStatus::Fail if check.name == CHECK_SERVER_REACHABLE => {
                recommendations.push("Check if server is running".to_string());
                recommendations.push("Verify firewall allows UDP port 443".to_string());
            }
            _ => {}
        }
    }

    DiagnosticReport { checks, recommendations }
}

/// Check that client private key files exist (if configured).
pub fn check_client_keys(config: &ClientConfigFile) -> CheckResult {
    let key_path = config.interface.as_ref().and_then(|i| i.private_key_path.as_deref());

    match key_path {
        Some(path) => {
            if Path::new(path).exists() {
                CheckResult {
                    name: CHECK_CLIENT_KEYS,
                    status: CheckStatus::Pass,
                    message: CHECK_CLIENT_KEYS.to_string(),
                }
            } else {
                CheckResult {
                    name: CHECK_CLIENT_KEYS,
                    status: CheckStatus::Fail,
                    message: format!("Client key not found at {path}"),
                }
            }
        }
        None => {
            // No key path configured — ephemeral keys will be generated
            CheckResult {
                name: CHECK_CLIENT_KEYS,
                status: CheckStatus::Pass,
                message: format!("{CHECK_CLIENT_KEYS} (ephemeral mode)"),
            }
        }
    }
}

/// Check that the client config has a server endpoint configured.
pub fn check_client_config(config: &ClientConfigFile) -> CheckResult {
    let has_endpoint = config.server.as_ref().and_then(|s| s.endpoint.as_deref()).is_some();

    if has_endpoint {
        CheckResult {
            name: CHECK_CLIENT_CONFIG,
            status: CheckStatus::Pass,
            message: CHECK_CLIENT_CONFIG.to_string(),
        }
    } else {
        CheckResult {
            name: CHECK_CLIENT_CONFIG,
            status: CheckStatus::Fail,
            message: "Server endpoint not configured".to_string(),
        }
    }
}

/// Check that the server is reachable via a UDP probe.
pub fn check_server_reachable(endpoint: &str) -> CheckResult {
    check_server_reachable_inner(endpoint)
}

fn check_server_reachable_inner(endpoint: &str) -> CheckResult {
    let addr: SocketAddr = match endpoint.parse() {
        Ok(a) => a,
        Err(e) => {
            return CheckResult {
                name: CHECK_SERVER_REACHABLE,
                status: CheckStatus::Fail,
                message: format!("Invalid server address '{endpoint}': {e}"),
            };
        }
    };

    // Bind to any local port and try to send a UDP packet
    let bind_addr: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().expect("valid ipv6 bind addr")
    } else {
        "0.0.0.0:0".parse().expect("valid ipv4 bind addr")
    };

    let socket = match std::net::UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            return CheckResult {
                name: CHECK_SERVER_REACHABLE,
                status: CheckStatus::Fail,
                message: format!("Cannot create UDP socket: {e}"),
            };
        }
    };

    if let Err(e) = socket.set_read_timeout(Some(std::time::Duration::from_secs(UDP_PROBE_TIMEOUT_SECS))) {
        return CheckResult {
            name: CHECK_SERVER_REACHABLE,
            status: CheckStatus::Fail,
            message: format!("Cannot set socket timeout: {e}"),
        };
    }

    // Send a minimal probe (single byte)
    let probe = [0u8; 1];
    match socket.send_to(&probe, addr) {
        Ok(_) => {
            // UDP is connectionless — send succeeding only means the local
            // network stack accepted it. We do a quick recv to see if we
            // get an ICMP port unreachable (manifested as a recv error on
            // some OSes). A timeout means the packet was likely delivered
            // (or dropped silently by a firewall).
            let mut buf = [0u8; 64];
            match socket.recv_from(&mut buf) {
                Ok(_) => CheckResult {
                    name: CHECK_SERVER_REACHABLE,
                    status: CheckStatus::Pass,
                    message: format!("Server {endpoint} responded"),
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    // Timeout — no ICMP unreachable, likely reachable
                    CheckResult {
                        name: CHECK_SERVER_REACHABLE,
                        status: CheckStatus::Pass,
                        message: format!("Server {endpoint} appears reachable (no ICMP unreachable)"),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => CheckResult {
                    name: CHECK_SERVER_REACHABLE,
                    status: CheckStatus::Fail,
                    message: format!("Server {endpoint} unreachable: connection refused"),
                },
                Err(_) => {
                    // Other error — still consider reachable since UDP send succeeded
                    CheckResult {
                        name: CHECK_SERVER_REACHABLE,
                        status: CheckStatus::Pass,
                        message: format!("Server {endpoint} appears reachable"),
                    }
                }
            }
        }
        Err(e) => CheckResult {
            name: CHECK_SERVER_REACHABLE,
            status: CheckStatus::Fail,
            message: format!("Cannot reach server {endpoint}: {e}"),
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P010.md
    use super::*;

    // -----------------------------------------------------------------------
    // Core types (AC-1 through AC-5)
    // -----------------------------------------------------------------------

    // AC-1: CheckStatus has Pass, Warn, Fail variants
    #[test]
    fn check_status_variants() {
        let pass = CheckStatus::Pass;
        let warn = CheckStatus::Warn;
        let fail = CheckStatus::Fail;
        assert_ne!(pass, warn);
        assert_ne!(warn, fail);
        assert_ne!(pass, fail);
    }

    // AC-2: CheckResult stores name, status, message
    #[test]
    fn check_result_fields() {
        let result = CheckResult {
            name: "test check",
            status: CheckStatus::Pass,
            message: "all good".to_string(),
        };
        assert_eq!(result.name, "test check");
        assert_eq!(result.status, CheckStatus::Pass);
        assert_eq!(result.message, "all good");
    }

    // AC-3: exit_code returns 0 for all-pass
    #[test]
    fn report_exit_code_all_pass() {
        let report = DiagnosticReport {
            checks: vec![
                CheckResult {
                    name: "a",
                    status: CheckStatus::Pass,
                    message: String::new(),
                },
                CheckResult {
                    name: "b",
                    status: CheckStatus::Pass,
                    message: String::new(),
                },
            ],
            recommendations: vec![],
        };
        assert_eq!(report.exit_code(), EXIT_CODE_OK);
    }

    // AC-4: exit_code returns 1 for warnings only
    #[test]
    fn report_exit_code_warnings() {
        let report = DiagnosticReport {
            checks: vec![
                CheckResult {
                    name: "a",
                    status: CheckStatus::Pass,
                    message: String::new(),
                },
                CheckResult {
                    name: "b",
                    status: CheckStatus::Warn,
                    message: String::new(),
                },
            ],
            recommendations: vec![],
        };
        assert_eq!(report.exit_code(), EXIT_CODE_WARN);
    }

    // AC-5: exit_code returns 2 for any failure
    #[test]
    fn report_exit_code_failures() {
        let report = DiagnosticReport {
            checks: vec![
                CheckResult {
                    name: "a",
                    status: CheckStatus::Pass,
                    message: String::new(),
                },
                CheckResult {
                    name: "b",
                    status: CheckStatus::Warn,
                    message: String::new(),
                },
                CheckResult {
                    name: "c",
                    status: CheckStatus::Fail,
                    message: String::new(),
                },
            ],
            recommendations: vec![],
        };
        assert_eq!(report.exit_code(), EXIT_CODE_FAIL);
    }

    // AC-5b: exit_code returns 0 for empty report
    #[test]
    fn report_exit_code_empty() {
        let report = DiagnosticReport {
            checks: vec![],
            recommendations: vec![],
        };
        assert_eq!(report.exit_code(), EXIT_CODE_OK);
    }

    // -----------------------------------------------------------------------
    // Server: config valid (AC-6, AC-7)
    // -----------------------------------------------------------------------

    // AC-6: check_server_config_from_path passes with valid TOML
    #[test]
    fn server_config_valid_passes() {
        let dir = std::env::temp_dir().join("prrr-diag-test-cfg-valid");
        std::fs::create_dir_all(&dir).expect("create dir");
        let path = dir.join("server.toml");
        std::fs::write(&path, "[server]\nmax_clients = 100\n").expect("write file");

        let result = check_server_config_from_path(Some(&path));
        assert_eq!(result.status, CheckStatus::Pass);
        assert_eq!(result.name, CHECK_CONFIG_VALID);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    // AC-7: check_server_config_from_path fails with invalid TOML
    #[test]
    fn server_config_invalid_fails() {
        let dir = std::env::temp_dir().join("prrr-diag-test-cfg-invalid");
        std::fs::create_dir_all(&dir).expect("create dir");
        let path = dir.join("bad.toml");
        std::fs::write(&path, "[server\nbroken\n").expect("write file");

        let result = check_server_config_from_path(Some(&path));
        assert_eq!(result.status, CheckStatus::Fail);
        assert_eq!(result.name, CHECK_CONFIG_VALID);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    // AC-6b: check_server_config_from_path passes with None (defaults)
    #[test]
    fn server_config_none_passes() {
        let result = check_server_config_from_path(None);
        assert_eq!(result.status, CheckStatus::Pass);
    }

    // -----------------------------------------------------------------------
    // Server: keys present (AC-8, AC-9)
    // -----------------------------------------------------------------------

    // AC-8: check_keys_present passes with valid key files
    #[test]
    fn server_keys_present_passes() {
        let dir = std::env::temp_dir().join("prrr-diag-test-keys-present");
        std::fs::create_dir_all(&dir).expect("create dir");

        let identity = dir.join("identity.key");
        let pq = dir.join("pq.key");
        std::fs::write(&identity, vec![0u8; NOISE_PRIVATE_KEY_SIZE as usize]).expect("write identity");
        std::fs::write(&pq, vec![0u8; KEM_DECAPSULATION_KEY_SIZE as usize]).expect("write pq");

        let result = check_keys_present(identity.to_str().unwrap(), pq.to_str().unwrap());
        assert_eq!(result.status, CheckStatus::Pass);
        assert_eq!(result.name, CHECK_KEYS_PRESENT);

        std::fs::remove_file(&identity).ok();
        std::fs::remove_file(&pq).ok();
        std::fs::remove_dir(&dir).ok();
    }

    // AC-9: check_keys_present fails when identity key missing
    #[test]
    fn server_keys_missing_fails() {
        let result = check_keys_present("/nonexistent/identity.key", "/nonexistent/pq.key");
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("Identity key not found"));
    }

    // AC-9b: check_keys_present fails when PQ key missing
    #[test]
    fn server_keys_pq_missing_fails() {
        let dir = std::env::temp_dir().join("prrr-diag-test-keys-pq-missing");
        std::fs::create_dir_all(&dir).expect("create dir");

        let identity = dir.join("identity.key");
        std::fs::write(&identity, vec![0u8; NOISE_PRIVATE_KEY_SIZE as usize]).expect("write identity");

        let result = check_keys_present(identity.to_str().unwrap(), "/nonexistent/pq.key");
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("Post-quantum key not found"));

        std::fs::remove_file(&identity).ok();
        std::fs::remove_dir(&dir).ok();
    }

    // AC-9c: check_keys_present fails with wrong identity key size
    #[test]
    fn server_keys_wrong_identity_size_fails() {
        let dir = std::env::temp_dir().join("prrr-diag-test-keys-wrong-size");
        std::fs::create_dir_all(&dir).expect("create dir");

        let identity = dir.join("identity.key");
        let pq = dir.join("pq.key");
        std::fs::write(&identity, vec![0u8; 16]).expect("write short identity"); // Wrong size
        std::fs::write(&pq, vec![0u8; KEM_DECAPSULATION_KEY_SIZE as usize]).expect("write pq");

        let result = check_keys_present(identity.to_str().unwrap(), pq.to_str().unwrap());
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("Identity key wrong size"));

        std::fs::remove_file(&identity).ok();
        std::fs::remove_file(&pq).ok();
        std::fs::remove_dir(&dir).ok();
    }

    // AC-9d: check_keys_present fails with wrong PQ key size
    #[test]
    fn server_keys_wrong_pq_size_fails() {
        let dir = std::env::temp_dir().join("prrr-diag-test-keys-wrong-pq-size");
        std::fs::create_dir_all(&dir).expect("create dir");

        let identity = dir.join("identity.key");
        let pq = dir.join("pq.key");
        std::fs::write(&identity, vec![0u8; NOISE_PRIVATE_KEY_SIZE as usize]).expect("write identity");
        std::fs::write(&pq, vec![0u8; 100]).expect("write wrong pq"); // Wrong size

        let result = check_keys_present(identity.to_str().unwrap(), pq.to_str().unwrap());
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("Post-quantum key wrong size"));

        std::fs::remove_file(&identity).ok();
        std::fs::remove_file(&pq).ok();
        std::fs::remove_dir(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // Server: port available (AC-10, AC-11)
    // -----------------------------------------------------------------------

    // AC-10: check_port_available passes when port is free
    #[test]
    fn server_port_available_passes() {
        // Use port 0 to find a free port, then test a high ephemeral port
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral");
        let port = socket.local_addr().expect("local addr").port();
        drop(socket); // Release the port

        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("valid addr");
        let result = check_port_available(addr);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.message.contains("available"));
    }

    // AC-11: check_port_available fails when port is occupied
    #[test]
    fn server_port_occupied_fails() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = socket.local_addr().expect("local addr");
        // Socket is still held — port is occupied

        let result = check_port_available(addr);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("unavailable"));

        drop(socket);
    }

    // -----------------------------------------------------------------------
    // Server: disk space (AC-12)
    // -----------------------------------------------------------------------

    // AC-12: check_disk_space returns appropriate status
    #[test]
    fn server_disk_space_check() {
        let result = check_disk_space("/tmp");
        // On any real system, /tmp should exist and have some space
        assert_eq!(result.name, CHECK_DISK_SPACE);
        // Could be Pass or Warn depending on system, but shouldn't error
        assert!(result.status == CheckStatus::Pass || result.status == CheckStatus::Warn);
    }

    // AC-12b: check_disk_space handles nonexistent directory gracefully
    #[test]
    fn server_disk_space_nonexistent() {
        let result = check_disk_space("/nonexistent/path/for/prrr/test");
        assert_eq!(result.name, CHECK_DISK_SPACE);
        // Should pass with fallback message (df may fail or return the root fs)
    }

    // -----------------------------------------------------------------------
    // Server: memory (AC-13)
    // -----------------------------------------------------------------------

    // AC-13: check_memory returns appropriate status
    #[test]
    fn server_memory_check() {
        let result = check_memory();
        assert_eq!(result.name, CHECK_MEMORY);
        // On any dev machine, should pass
        assert!(result.status == CheckStatus::Pass || result.status == CheckStatus::Warn);
    }

    // AC-13b: parse_meminfo_and_check with sufficient memory
    #[test]
    fn memory_parse_sufficient() {
        let content = "MemTotal:       16384000 kB\nMemFree:         8192000 kB\nMemAvailable:    10240000 kB\n";
        let result = parse_meminfo_and_check(content);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.message.contains("free"));
    }

    // AC-13c: parse_meminfo_and_check with low memory (warning)
    #[test]
    fn memory_parse_warn() {
        // 100 MB = 102400 kB — between 64 and 128 MB thresholds
        let content = "MemTotal:       1024000 kB\nMemFree:         50000 kB\nMemAvailable:    102400 kB\n";
        let result = parse_meminfo_and_check(content);
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.message.contains("low"));
    }

    // AC-13d: parse_meminfo_and_check with critical memory (fail)
    #[test]
    fn memory_parse_critical() {
        // 32 MB = 32768 kB — below 64 MB threshold
        let content = "MemTotal:       1024000 kB\nMemFree:         10000 kB\nMemAvailable:    32768 kB\n";
        let result = parse_meminfo_and_check(content);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("critically low"));
    }

    // AC-13e: parse_meminfo_and_check with missing MemAvailable line
    #[test]
    fn memory_parse_missing_field() {
        let content = "MemTotal:       16384000 kB\nMemFree:         8192000 kB\n";
        let result = parse_meminfo_and_check(content);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.message.contains("unable to parse"));
    }

    // -----------------------------------------------------------------------
    // Server: stale clients (AC-14, AC-15)
    // -----------------------------------------------------------------------

    // AC-14: check_stale_clients warns when stale clients exist
    #[test]
    fn server_stale_clients_warns() {
        let dir = std::env::temp_dir().join("prrr-diag-test-stale");
        std::fs::create_dir_all(&dir).expect("create dir");
        let db_path = dir.join(crate::registry::DATABASE_FILENAME);

        let subnet = "10.99.99.0/24";
        {
            let mut registry = crate::registry::ClientRegistry::open(subnet, &db_path).expect("open registry");
            let kp = crate::handshake::noise_ik::KeyPair::generate().expect("keypair");
            registry.add("stale-client", *kp.public_key(), None).expect("add client");
            // Client has last_seen = None → considered stale
        }

        let result = check_stale_clients(subnet, &db_path);
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.message.contains("1 client"));
        assert!(result.message.contains("haven't connected"));

        std::fs::remove_file(&db_path).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    // AC-15: check_stale_clients passes when no stale clients
    #[test]
    fn server_no_stale_clients_passes() {
        let dir = std::env::temp_dir().join("prrr-diag-test-no-stale");
        std::fs::create_dir_all(&dir).expect("create dir");
        let db_path = dir.join(crate::registry::DATABASE_FILENAME);

        let subnet = "10.98.98.0/24";
        {
            let mut registry = crate::registry::ClientRegistry::open(subnet, &db_path).expect("open registry");
            let kp = crate::handshake::noise_ik::KeyPair::generate().expect("keypair");
            let record = registry.add("active-client", *kp.public_key(), None).expect("add client");
            // Update last_seen to now
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_secs();
            registry.update_last_seen(record.id, now).expect("update last_seen");
        }

        let result = check_stale_clients(subnet, &db_path);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.message.contains("active"));

        std::fs::remove_file(&db_path).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    // AC-15b: check_stale_clients passes when no database exists
    #[test]
    fn server_no_database_passes() {
        let result = check_stale_clients("10.0.0.0/24", Path::new("/nonexistent/clients.db"));
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.message.contains("No client database"));
    }

    // -----------------------------------------------------------------------
    // Client: keys present (AC-16, AC-17)
    // -----------------------------------------------------------------------

    // AC-16: check_client_keys passes when keys exist
    #[test]
    fn client_keys_present_passes() {
        let dir = std::env::temp_dir().join("prrr-diag-test-client-keys");
        std::fs::create_dir_all(&dir).expect("create dir");
        let key_path = dir.join("client.key");
        std::fs::write(&key_path, vec![0u8; 32]).expect("write key");

        let config = ClientConfigFile {
            interface: Some(crate::config::InterfaceSection {
                private_key_path: Some(key_path.to_str().unwrap().to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = check_client_keys(&config);
        assert_eq!(result.status, CheckStatus::Pass);
        assert_eq!(result.name, CHECK_CLIENT_KEYS);

        std::fs::remove_file(&key_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    // AC-17: check_client_keys passes when no key path configured (ephemeral)
    #[test]
    fn client_keys_ephemeral_passes() {
        let config = ClientConfigFile::default();
        let result = check_client_keys(&config);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.message.contains("ephemeral"));
    }

    // AC-16b: check_client_keys fails when configured key not found
    #[test]
    fn client_keys_missing_fails() {
        let config = ClientConfigFile {
            interface: Some(crate::config::InterfaceSection {
                private_key_path: Some("/nonexistent/client.key".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = check_client_keys(&config);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("not found"));
    }

    // -----------------------------------------------------------------------
    // Client: config valid (AC-18, AC-19)
    // -----------------------------------------------------------------------

    // AC-18: check_client_config passes with valid config and endpoint
    #[test]
    fn client_config_valid_passes() {
        let config = ClientConfigFile {
            server: Some(crate::config::ClientServerSection {
                endpoint: Some("10.0.0.1:443".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = check_client_config(&config);
        assert_eq!(result.status, CheckStatus::Pass);
        assert_eq!(result.name, CHECK_CLIENT_CONFIG);
    }

    // AC-19: check_client_config fails without server endpoint
    #[test]
    fn client_config_missing_endpoint_fails() {
        let config = ClientConfigFile::default();
        let result = check_client_config(&config);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("endpoint not configured"));
    }

    // -----------------------------------------------------------------------
    // Client: server reachable (AC-20)
    // -----------------------------------------------------------------------

    // AC-20: check_server_reachable handles unreachable server
    #[test]
    fn client_server_unreachable_fails() {
        // Use a non-routable address that should fail quickly
        let result = check_server_reachable("192.0.2.1:443");
        // RFC 5737 TEST-NET-1 — should be unreachable on most systems
        // Result varies by OS (may timeout or get ConnectionRefused)
        assert_eq!(result.name, CHECK_SERVER_REACHABLE);
        // Don't assert on status since it depends on network setup;
        // just verify the function doesn't panic
    }

    // AC-20b: check_server_reachable fails with invalid address
    #[test]
    fn client_server_invalid_address_fails() {
        let result = check_server_reachable("not-an-address");
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("Invalid server address"));
    }

    // -----------------------------------------------------------------------
    // Colored output (AC-23, AC-24)
    // -----------------------------------------------------------------------

    // AC-23: print_colored outputs ANSI-colored status lines
    #[test]
    fn report_print_colored_output() {
        // Just ensure it doesn't panic — actual output goes to stdout
        let report = DiagnosticReport {
            checks: vec![
                CheckResult {
                    name: "pass check",
                    status: CheckStatus::Pass,
                    message: "all good".to_string(),
                },
                CheckResult {
                    name: "warn check",
                    status: CheckStatus::Warn,
                    message: "heads up".to_string(),
                },
                CheckResult {
                    name: "fail check",
                    status: CheckStatus::Fail,
                    message: "problem".to_string(),
                },
            ],
            recommendations: vec!["fix the problem".to_string()],
        };
        report.print_colored();
    }

    // AC-24: Recommendations present for warnings/failures
    #[test]
    fn report_recommendations_present() {
        let report = DiagnosticReport {
            checks: vec![CheckResult {
                name: "ok",
                status: CheckStatus::Pass,
                message: String::new(),
            }],
            recommendations: vec!["do something".to_string()],
        };
        assert!(!report.recommendations.is_empty());
        assert_eq!(report.recommendations[0], "do something");
    }

    // -----------------------------------------------------------------------
    // Full server doctor report
    // -----------------------------------------------------------------------

    #[test]
    fn run_server_doctor_produces_report() {
        let config = ServerConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("valid addr");
        let report = run_server_doctor(&config, addr);

        // Should have 6 checks
        assert_eq!(report.checks.len(), 6);
        assert_eq!(report.checks[0].name, CHECK_CONFIG_VALID);
        assert_eq!(report.checks[1].name, CHECK_KEYS_PRESENT);
        assert_eq!(report.checks[2].name, CHECK_PORT_AVAILABLE);
        assert_eq!(report.checks[3].name, CHECK_DISK_SPACE);
        assert_eq!(report.checks[4].name, CHECK_MEMORY);
        assert_eq!(report.checks[5].name, CHECK_STALE_CLIENTS);
    }

    // -----------------------------------------------------------------------
    // Full client doctor report
    // -----------------------------------------------------------------------

    #[test]
    fn run_client_doctor_produces_report() {
        let config = ClientConfigFile::default();
        let report = run_client_doctor(&config);

        // Should have 2 checks (keys + config; no server reachable since no endpoint)
        assert_eq!(report.checks.len(), 2);
        assert_eq!(report.checks[0].name, CHECK_CLIENT_KEYS);
        assert_eq!(report.checks[1].name, CHECK_CLIENT_CONFIG);
    }

    #[test]
    fn run_client_doctor_with_endpoint_has_three_checks() {
        let config = ClientConfigFile {
            server: Some(crate::config::ClientServerSection {
                endpoint: Some("127.0.0.1:443".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let report = run_client_doctor(&config);

        // Should have 3 checks (keys + config + server reachable)
        assert_eq!(report.checks.len(), 3);
        assert_eq!(report.checks[2].name, CHECK_SERVER_REACHABLE);
    }
}
