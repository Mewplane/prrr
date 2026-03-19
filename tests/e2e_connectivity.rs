//! Rust-native connectivity e2e tests using PodmanOrchestrator.
//!
//! Tests actual VPN tunnel establishment with real server in Docker
//! and real client, verifying packet flow through the tunnel.
//!
//! All tests are `#[ignore]` — they require Podman, `/dev/net/tun`,
//! and `NET_ADMIN` capability:
//!
//! ```bash
//! cargo test --test e2e_connectivity -- --ignored
//! ```

mod support;

use std::time::Duration;
use support::podman::{PodmanOrchestrator, Container};

const SERVER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const TUNNEL_TIMEOUT: Duration = Duration::from_secs(30);
const VPN_GATEWAY: &str = "10.66.66.1";

/// Run a full tunnel test for the given transport.
fn run_tunnel_test(test_name: &str, transport: &str) {
    let mut orch = PodmanOrchestrator::new(test_name);

    orch.build_image().expect("build image");
    orch.create_network().expect("create network");
    orch.create_volume().expect("create volume");

    let server_ip = orch.start_server(transport).expect("start server");
    orch.wait_for_server_ready(SERVER_READY_TIMEOUT)
        .unwrap_or_else(|e| {
            let logs = orch.logs(Container::Server).unwrap_or_default();
            panic!("server not ready: {e}\n--- server logs ---\n{logs}");
        });

    orch.start_client(&server_ip, transport).expect("start client");
    orch.wait_for_tunnel(TUNNEL_TIMEOUT)
        .unwrap_or_else(|e| {
            let logs = orch.logs(Container::Client).unwrap_or_default();
            panic!("tunnel not established: {e}\n--- client logs ---\n{logs}");
        });

    let ping_ok = orch.ping(Container::Client, VPN_GATEWAY)
        .expect("ping command");
    if !ping_ok {
        let client_logs = orch.logs(Container::Client).unwrap_or_default();
        let server_logs = orch.logs(Container::Server).unwrap_or_default();
        panic!(
            "ping through VPN failed\n--- client logs ---\n{client_logs}\n--- server logs ---\n{server_logs}"
        );
    }
}

// ---------------------------------------------------------------------------
// Per-transport tunnel tests
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn e2e_masque_tunnel() {
    run_tunnel_test("masque", "masque");
}

#[test]
#[ignore]
fn e2e_harp_tunnel() {
    run_tunnel_test("harp", "harp");
}

// ---------------------------------------------------------------------------
// Prerequisites check (not #[ignore] — runs in normal test suite)
// ---------------------------------------------------------------------------

#[test]
fn e2e_containerfile_exists() {
    assert!(
        std::path::Path::new("deploy/client/Containerfile").exists(),
        "deploy/client/Containerfile must exist"
    );
}

#[test]
fn e2e_entrypoint_exists_and_executable() {
    let path = std::path::Path::new("deploy/client/entrypoint.sh");
    assert!(path.exists(), "entrypoint.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).expect("metadata").permissions().mode();
        assert!(mode & 0o111 != 0, "entrypoint.sh must be executable");
    }
}

#[test]
fn e2e_entrypoint_supports_transport_selection() {
    let content = std::fs::read_to_string("deploy/client/entrypoint.sh")
        .expect("read entrypoint.sh");

    assert!(content.contains("PRRR_TRANSPORT"), "must support PRRR_TRANSPORT env var");
    assert!(content.contains("[[transports]]"), "must use [[transports]] array config");
    assert!(content.contains("name = \"masque\""), "must configure masque transport");
}
