//! Client/tunnel-specific Podman helpers.
//!
//! These extend [`PodmanOrchestrator`] for e2e binaries that drive a *client*
//! container in addition to the server. Server-only binaries (e.g. the Android
//! emulator flow) do not include this file, so its surface stays out of their
//! dead-code analysis.

#[path = "podman.rs"]
mod podman;

use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

pub use podman::PodmanOrchestrator;

impl PodmanOrchestrator {
    /// Start the client container.
    pub fn start_client(&mut self, server_ip: &str, transport: &str) -> Result<(), String> {
        let container_name = format!("prrr-client-{}", self.test_name);

        let _ = Command::new("podman").args(["rm", "-f", &container_name]).output();

        let volume_mount = format!("{}:/shared:z", self.volume_name);
        let output = Command::new("podman")
            .args([
                "run",
                "-d",
                "--name",
                &container_name,
                "--network",
                &self.network_name,
                "--cap-add=NET_ADMIN",
                "--cap-add=NET_RAW",
                "--device=/dev/net/tun",
                "--security-opt",
                "label=disable",
                "-v",
                &volume_mount,
                "-e",
                "PRRR_MODE=client",
                "-e",
                &format!("PRRR_TRANSPORT={transport}"),
                "-e",
                "PRRR_LOG_LEVEL=info",
                "-e",
                &format!("PRRR_SERVER_ENDPOINT={server_ip}:443"),
                "-e",
                &format!("PRRR_SERVER_NAME={server_ip}"),
                "-e",
                "PRRR_SHARED_DIR=/shared",
                "-e",
                "PRRR_CLIENT_NAME=e2e-client",
                &self.image_name,
            ])
            .output()
            .map_err(|e| format!("podman run client: {e}"))?;

        if !output.status.success() {
            return Err(format!("podman run client failed:\n{}", String::from_utf8_lossy(&output.stderr)));
        }

        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        self.client_id = Some(id);
        Ok(())
    }

    /// Wait for the client tunnel to establish (checks for prrr0 or tun0 interface).
    pub fn wait_for_tunnel(&self, timeout: Duration) -> Result<(), String> {
        let start = Instant::now();
        let container = self.client_id.as_ref().ok_or("client not started")?;

        while start.elapsed() < timeout {
            let output = Command::new("podman")
                .args(["exec", container, "ip", "link"])
                .output()
                .map_err(|e| format!("podman exec: {e}"))?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("prrr0") || stdout.contains("tun0") {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err(format!("tunnel not established after {timeout:?}"))
    }

    /// Ping a target IP from the client container.
    pub fn client_ping(&self, target_ip: &str) -> Result<bool, String> {
        let id = self.client_id.as_deref().ok_or("client not started")?;
        let output = self.exec_in(id, &["ping", "-c", "3", "-W", "5", target_ip])?;
        Ok(output.status.success())
    }

    /// Get the client container logs.
    pub fn client_logs(&self) -> Result<String, String> {
        let id = self.client_id.as_deref().ok_or("client not started")?;
        self.logs_of(id)
    }
}
