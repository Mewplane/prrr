// FRD: specs/frds/FRD-20260223-podman-e2e-infrastructure.md
// FRD: specs/frds/FRD-20260223-podman-e2e-multi-transport.md

//! Podman-based end-to-end integration tests for prrr VPN.
//!
//! These tests require Podman, `/dev/net/tun`, and `NET_ADMIN` capability.
//! They are `#[ignore]` by default — run with:
//!
//! ```bash
//! cargo test --test e2e_podman -- --ignored
//! ```
//!
//! Or via Makefile:
//!
//! ```bash
//! make podman-e2e
//! ```

use std::process::Command;

/// Path to the E2E orchestration script.
const RUN_SCRIPT: &str = "deploy/client/run-podman.sh";

/// Marker string emitted by run-podman.sh on success.
const PASS_MARKER: &str = "E2E TEST RESULT: PASS";

/// Marker string emitted by run-podman.sh on failure.
const FAIL_MARKER: &str = "E2E TEST RESULT: FAIL";

/// Check that Podman is installed and reachable.
fn podman_available() -> bool {
    Command::new("podman")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check that `/dev/net/tun` exists (required for TUN devices in containers).
fn tun_device_available() -> bool {
    std::path::Path::new("/dev/net/tun").exists()
}

/// Run the E2E script and return (exit_code, stdout, stderr).
///
/// The script has internal timeouts for each phase (server startup, client
/// connection, connectivity test), so no external timeout is needed here.
fn run_e2e_script() -> (i32, String, String) {
    run_e2e_with_transport("masque")
}

/// Run the E2E script with a specific transport and return (exit_code, stdout, stderr).
fn run_e2e_with_transport(transport: &str) -> (i32, String, String) {
    let output = Command::new("bash")
        .arg(RUN_SCRIPT)
        .env("PRRR_LOG_LEVEL", "info")
        .env("PRRR_TRANSPORT", transport)
        .output()
        .expect("failed to execute run-podman.sh");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (exit_code, stdout, stderr)
}

// ---------------------------------------------------------------------------
// AC-4 / AC-5: Full E2E test — build image, run server+client, test tunnel
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn e2e_podman_full_tunnel_test() {
    if !podman_available() {
        eprintln!("SKIP: Podman not available");
        return;
    }
    if !tun_device_available() {
        eprintln!("SKIP: /dev/net/tun not available");
        return;
    }

    let (exit_code, stdout, stderr) = run_e2e_script();

    // Print output for CI visibility
    println!("--- stdout ---\n{stdout}");
    if !stderr.is_empty() {
        println!("--- stderr ---\n{stderr}");
    }

    assert!(
        stdout.contains(PASS_MARKER),
        "E2E test did not produce PASS marker. Exit code: {exit_code}"
    );
    assert!(!stdout.contains(FAIL_MARKER), "E2E test produced FAIL marker");
    assert_eq!(exit_code, 0, "run-podman.sh exited with non-zero code");
}

// ---------------------------------------------------------------------------
// AC-6: Script existence and executability
// ---------------------------------------------------------------------------

#[test]
fn e2e_podman_script_exists() {
    let path = std::path::Path::new(RUN_SCRIPT);
    assert!(path.exists(), "run-podman.sh missing: {RUN_SCRIPT}");
    assert!(path.is_file(), "run-podman.sh is not a file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(path).expect("metadata").permissions();
        assert!(perms.mode() & 0o111 != 0, "run-podman.sh is not executable");
    }
}

#[test]
fn e2e_podman_entrypoint_exists() {
    let path = std::path::Path::new("deploy/client/entrypoint.sh");
    assert!(path.exists(), "entrypoint.sh missing");
    assert!(path.is_file(), "entrypoint.sh is not a file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(path).expect("metadata").permissions();
        assert!(perms.mode() & 0o111 != 0, "entrypoint.sh is not executable");
    }
}

#[test]
fn e2e_podman_containerfile_exists() {
    let path = std::path::Path::new("deploy/client/Containerfile");
    assert!(path.exists(), "Containerfile missing");
    assert!(path.is_file(), "Containerfile is not a file");
}

// ---------------------------------------------------------------------------
// AC-8: Scripts use configurable env vars (no hardcoded paths)
// ---------------------------------------------------------------------------

#[test]
fn e2e_podman_script_uses_env_vars() {
    let content = std::fs::read_to_string(RUN_SCRIPT).expect("read run-podman.sh");

    let required_vars = [
        "PRRR_IMAGE_NAME",
        "PRRR_IMAGE_TAG",
        "PRRR_POD_NAME",
        "PRRR_SUBNET",
        "PRRR_LISTEN_PORT",
        "PRRR_LOG_LEVEL",
        "PRRR_STARTUP_WAIT",
        "PRRR_CLIENT_WAIT",
        "PRRR_TEST_TIMEOUT",
        "PRRR_SKIP_BUILD",
    ];
    for var in required_vars {
        assert!(content.contains(var), "run-podman.sh must reference env var {var}");
    }
}

#[test]
fn e2e_podman_entrypoint_uses_env_vars() {
    let content = std::fs::read_to_string("deploy/client/entrypoint.sh").expect("read entrypoint.sh");

    let required_vars = [
        "PRRR_MODE",
        "PRRR_LISTEN_ADDR",
        "PRRR_SUBNET",
        "PRRR_MAX_CLIENTS",
        "PRRR_LOG_LEVEL",
        "PRRR_DATA_DIR",
        "PRRR_SHARED_DIR",
        "PRRR_CLIENT_NAME",
        "PRRR_SERVER_NAME",
        "PRRR_SERVER_ENDPOINT",
    ];
    for var in required_vars {
        assert!(content.contains(var), "entrypoint.sh must reference env var {var}");
    }
}

// ---------------------------------------------------------------------------
// Script quality: strict mode and shebang
// ---------------------------------------------------------------------------

#[test]
fn e2e_podman_scripts_strict_mode() {
    for script in &[RUN_SCRIPT, "deploy/client/entrypoint.sh"] {
        let content = std::fs::read_to_string(script).unwrap_or_else(|e| panic!("read {script}: {e}"));
        assert!(
            content.starts_with("#!/usr/bin/env bash"),
            "{script} must start with #!/usr/bin/env bash"
        );
        assert!(
            content.contains("set -euo pipefail"),
            "{script} must use strict mode (set -euo pipefail)"
        );
    }
}

// ---------------------------------------------------------------------------
// Containerfile quality checks
// ---------------------------------------------------------------------------

#[test]
fn e2e_podman_containerfile_multistage() {
    let content = std::fs::read_to_string("deploy/client/Containerfile").expect("read Containerfile");

    assert!(content.contains("AS builder"), "Containerfile must have a builder stage");
    assert!(content.contains("AS runtime"), "Containerfile must have a runtime stage");
    assert!(
        content.contains("cargo build --release"),
        "Containerfile must build in release mode"
    );
    assert!(
        content.contains("COPY --from=builder"),
        "Containerfile must copy binary from builder stage"
    );
}

#[test]
fn e2e_podman_containerfile_runtime_deps() {
    let content = std::fs::read_to_string("deploy/client/Containerfile").expect("read Containerfile");

    assert!(content.contains("iproute2"), "Containerfile must install iproute2");
    assert!(content.contains("iptables"), "Containerfile must install iptables");
    assert!(
        content.contains("CAP_NET_ADMIN"),
        "Containerfile must document CAP_NET_ADMIN requirement"
    );
}

#[test]
fn e2e_podman_containerfile_cap_net_admin_documented() {
    let content = std::fs::read_to_string("deploy/client/Containerfile").expect("read Containerfile");

    assert!(
        content.contains("--cap-add=NET_ADMIN"),
        "Containerfile must document --cap-add=NET_ADMIN in comments"
    );
    assert!(
        content.contains("--device=/dev/net/tun"),
        "Containerfile must document --device=/dev/net/tun in comments"
    );
}

// ---------------------------------------------------------------------------
// AC-9: README exists with usage documentation
// ---------------------------------------------------------------------------

#[test]
fn e2e_podman_readme_exists() {
    let path = std::path::Path::new("deploy/client/README.md");
    assert!(path.exists(), "deploy/client/README.md must exist");

    let content = std::fs::read_to_string(path).expect("read README.md");
    assert!(content.contains("Podman"), "README must mention Podman");
    assert!(
        content.contains("podman-e2e") || content.contains("podman-build"),
        "README must mention Makefile targets"
    );
    assert!(content.contains("PRRR_"), "README must document environment variables");
    assert!(content.contains("Troubleshooting"), "README must have troubleshooting section");
}

// ---------------------------------------------------------------------------
// Multi-transport tests (Step 14)
// ---------------------------------------------------------------------------

// AC-1: entrypoint.sh uses [[transports]] array config
#[test]
fn e2e_podman_entrypoint_uses_transports_array() {
    let content = std::fs::read_to_string("deploy/client/entrypoint.sh").expect("read entrypoint.sh");
    assert!(
        content.contains("[[transports]]"),
        "entrypoint.sh must use [[transports]] array config"
    );
    assert!(
        content.contains("name = \"masque\""),
        "entrypoint.sh must configure masque transport"
    );
    assert!(content.contains("name = \"harp\""), "entrypoint.sh must configure harp transport");
}

// AC-2: entrypoint.sh supports PRRR_TRANSPORT env var
#[test]
fn e2e_podman_entrypoint_uses_transport_env() {
    let content = std::fs::read_to_string("deploy/client/entrypoint.sh").expect("read entrypoint.sh");
    assert!(
        content.contains("PRRR_TRANSPORT"),
        "entrypoint.sh must reference PRRR_TRANSPORT env var"
    );
    assert!(
        content.contains("transport_protocol"),
        "entrypoint.sh must support transport_protocol override in client config"
    );
}

// AC-3: run-podman.sh passes PRRR_TRANSPORT to client container
#[test]
fn e2e_podman_script_passes_transport_env() {
    let content = std::fs::read_to_string(RUN_SCRIPT).expect("read run-podman.sh");
    assert!(
        content.contains("PRRR_TRANSPORT"),
        "run-podman.sh must reference PRRR_TRANSPORT env var"
    );
}

// AC-4, AC-5, AC-6: Makefile has per-transport targets
#[test]
fn e2e_podman_makefile_has_transport_targets() {
    let content = std::fs::read_to_string("Makefile").expect("read Makefile");
    assert!(content.contains("podman-e2e-masque"), "Makefile must have podman-e2e-masque target");
    assert!(content.contains("podman-e2e-harp"), "Makefile must have podman-e2e-harp target");
    assert!(content.contains("podman-e2e-multi"), "Makefile must have podman-e2e-multi target");
}

// AC-5: HARP E2E tunnel test (requires Podman)
#[test]
#[ignore]
fn e2e_podman_harp_tunnel_test() {
    if !podman_available() {
        eprintln!("SKIP: Podman not available");
        return;
    }
    if !tun_device_available() {
        eprintln!("SKIP: /dev/net/tun not available");
        return;
    }

    let (exit_code, stdout, stderr) = run_e2e_with_transport("harp");

    println!("--- stdout ---\n{stdout}");
    if !stderr.is_empty() {
        println!("--- stderr ---\n{stderr}");
    }

    assert!(
        stdout.contains(PASS_MARKER),
        "HARP E2E test did not produce PASS marker. Exit code: {exit_code}"
    );
    assert!(!stdout.contains(FAIL_MARKER), "HARP E2E test produced FAIL marker");
    assert_eq!(exit_code, 0, "run-podman.sh (HARP) exited with non-zero code");
}

// AC-6, AC-7: Multi-transport E2E test (requires Podman)
#[test]
#[ignore]
fn e2e_podman_multi_transport_test() {
    if !podman_available() {
        eprintln!("SKIP: Podman not available");
        return;
    }
    if !tun_device_available() {
        eprintln!("SKIP: /dev/net/tun not available");
        return;
    }

    // Phase 1: MASQUE
    let (exit_code, stdout, stderr) = run_e2e_with_transport("masque");
    println!("--- MASQUE stdout ---\n{stdout}");
    if !stderr.is_empty() {
        println!("--- MASQUE stderr ---\n{stderr}");
    }
    assert!(
        stdout.contains(PASS_MARKER),
        "MASQUE phase did not produce PASS marker. Exit code: {exit_code}"
    );

    // Phase 2: HARP
    let (exit_code, stdout, stderr) = run_e2e_with_transport("harp");
    println!("--- HARP stdout ---\n{stdout}");
    if !stderr.is_empty() {
        println!("--- HARP stderr ---\n{stderr}");
    }
    assert!(
        stdout.contains(PASS_MARKER),
        "HARP phase did not produce PASS marker. Exit code: {exit_code}"
    );
}
