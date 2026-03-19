//! Rust-native Podman orchestration for e2e connectivity tests.
//!
//! Replaces bash script delegation with direct `podman` CLI calls.
//! The `Drop` implementation ensures cleanup even on test panic.

use std::process::{Command, Output};
use std::time::{Duration, Instant};
use std::thread;

/// Which container to target.
#[derive(Debug, Clone, Copy)]
pub enum Container {
    Server,
    Client,
}

/// Orchestrates Podman containers for VPN e2e tests.
pub struct PodmanOrchestrator {
    test_name: String,
    image_name: String,
    network_name: String,
    volume_name: String,
    server_id: Option<String>,
    client_id: Option<String>,
    server_ip: String,
}

impl PodmanOrchestrator {
    /// Create a new orchestrator. Names are derived from `test_name` to avoid conflicts.
    pub fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            image_name: "prrr-e2e".to_string(),
            network_name: format!("prrr-net-{test_name}"),
            volume_name: format!("prrr-vol-{test_name}"),
            server_id: None,
            client_id: None,
            server_ip: "10.89.0.10".to_string(),
        }
    }

    /// Check if podman is available.
    pub fn podman_available() -> bool {
        Command::new("podman")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if /dev/net/tun exists.
    pub fn tun_available() -> bool {
        std::path::Path::new("/dev/net/tun").exists()
    }

    /// Build the prrr container image from deploy/client/Containerfile.
    pub fn build_image(&self) -> Result<(), String> {
        let output = Command::new("podman")
            .args(["build", "-t", &self.image_name, "-f", "deploy/client/Containerfile", "."])
            .output()
            .map_err(|e| format!("podman build failed: {e}"))?;

        if !output.status.success() {
            return Err(format!(
                "podman build failed (exit {}):\n{}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }

    /// Create an isolated network for the test (podman picks a free subnet).
    pub fn create_network(&self) -> Result<(), String> {
        // Remove if leftover from a previous failed run
        let _ = Command::new("podman")
            .args(["network", "rm", "-f", &self.network_name])
            .output();

        let output = Command::new("podman")
            .args(["network", "create", &self.network_name])
            .output()
            .map_err(|e| format!("podman network create: {e}"))?;

        if !output.status.success() {
            return Err(format!(
                "podman network create failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }

    /// Create a shared volume for config exchange.
    pub fn create_volume(&self) -> Result<(), String> {
        let _ = Command::new("podman")
            .args(["volume", "rm", "-f", &self.volume_name])
            .output();

        let output = Command::new("podman")
            .args(["volume", "create", &self.volume_name])
            .output()
            .map_err(|e| format!("podman volume create: {e}"))?;

        if !output.status.success() {
            return Err(format!(
                "podman volume create failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }

    /// Start the server container. Returns the server IP.
    ///
    /// If `host_port` is Some, publishes the server port to the host (needed for
    /// emulator tests where the emulator reaches the host at 10.0.2.2).
    pub fn start_server(&mut self, transport: &str) -> Result<String, String> {
        self.start_server_with_opts(transport, None)
    }

    /// Start server with optional host port publish.
    pub fn start_server_with_opts(&mut self, transport: &str, host_port: Option<u16>) -> Result<String, String> {
        let container_name = format!("prrr-server-{}", self.test_name);

        // Remove if leftover
        let _ = Command::new("podman")
            .args(["rm", "-f", &container_name])
            .output();

        let volume_mount = format!("{}:/shared:z", self.volume_name);
        let port_publish = host_port.map(|p| format!("{p}:443/udp"));
        let port_publish_tcp = host_port.map(|p| format!("{p}:443/tcp"));
        let mut args = vec![
            "run".to_string(), "-d".to_string(),
            "--name".to_string(), container_name.clone(),
            "--network".to_string(), self.network_name.clone(),
            "--cap-add=NET_ADMIN".to_string(),
            "--cap-add=NET_RAW".to_string(),
            "--device=/dev/net/tun".to_string(),
            "--security-opt".to_string(), "label=disable".to_string(),
            "-v".to_string(), volume_mount,
        ];
        if let Some(ref pp) = port_publish {
            args.push("-p".to_string());
            args.push(pp.clone());
        }
        if let Some(ref pp) = port_publish_tcp {
            args.push("-p".to_string());
            args.push(pp.clone());
        }
        args.extend([
            "-e".to_string(), "PRRR_MODE=server".to_string(),
            "-e".to_string(), format!("PRRR_TRANSPORT={transport}"),
            "-e".to_string(), "PRRR_LOG_LEVEL=info".to_string(),
            "-e".to_string(), "PRRR_SUBNET=10.66.66.0/24".to_string(),
            "-e".to_string(), "PRRR_LISTEN_ADDR=0.0.0.0:443".to_string(),
            "-e".to_string(), "PRRR_SHARED_DIR=/shared".to_string(),
            "-e".to_string(), "PRRR_CLIENT_NAME=e2e-client".to_string(),
            self.image_name.clone(),
        ]);

        let output = Command::new("podman")
            .args(&args)
            .output()
            .map_err(|e| format!("podman run server: {e}"))?;

        if !output.status.success() {
            return Err(format!(
                "podman run server failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        self.server_id = Some(id.clone());

        // Discover the server's IP on our network
        let inspect = Command::new("podman")
            .args(["inspect", "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                &id])
            .output()
            .map_err(|e| format!("podman inspect: {e}"))?;

        let ip = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
        if ip.is_empty() {
            return Err("could not determine server IP".to_string());
        }
        self.server_ip = ip.clone();
        Ok(ip)
    }

    /// Wait for the server to be ready (checks for marker file in shared volume).
    pub fn wait_for_server_ready(&self, timeout: Duration) -> Result<(), String> {
        let start = Instant::now();
        let container = self.server_id.as_ref().ok_or("server not started")?;

        while start.elapsed() < timeout {
            let output = Command::new("podman")
                .args(["exec", container, "test", "-f", "/shared/server-ready"])
                .output()
                .map_err(|e| format!("podman exec: {e}"))?;

            if output.status.success() {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err(format!("server not ready after {:?}", timeout))
    }

    /// Start the client container.
    pub fn start_client(&mut self, server_ip: &str, transport: &str) -> Result<(), String> {
        let container_name = format!("prrr-client-{}", self.test_name);

        let _ = Command::new("podman")
            .args(["rm", "-f", &container_name])
            .output();

        let volume_mount = format!("{}:/shared:z", self.volume_name);
        let output = Command::new("podman")
            .args([
                "run", "-d",
                "--name", &container_name,
                "--network", &self.network_name,
                "--cap-add=NET_ADMIN",
                "--cap-add=NET_RAW",
                "--device=/dev/net/tun",
                "--security-opt", "label=disable",
                "-v", &volume_mount,
                "-e", "PRRR_MODE=client",
                "-e", &format!("PRRR_TRANSPORT={transport}"),
                "-e", "PRRR_LOG_LEVEL=info",
                "-e", &format!("PRRR_SERVER_ENDPOINT={server_ip}:443"),
                "-e", &format!("PRRR_SERVER_NAME={server_ip}"),
                "-e", "PRRR_SHARED_DIR=/shared",
                "-e", "PRRR_CLIENT_NAME=e2e-client",
                &self.image_name,
            ])
            .output()
            .map_err(|e| format!("podman run client: {e}"))?;

        if !output.status.success() {
            return Err(format!(
                "podman run client failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            ));
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
        Err(format!("tunnel not established after {:?}", timeout))
    }

    /// Ping from a container to a target IP.
    pub fn ping(&self, from: Container, target_ip: &str) -> Result<bool, String> {
        let container_id = match from {
            Container::Server => self.server_id.as_ref(),
            Container::Client => self.client_id.as_ref(),
        }.ok_or("container not started")?;

        let output = Command::new("podman")
            .args(["exec", container_id, "ping", "-c", "3", "-W", "5", target_ip])
            .output()
            .map_err(|e| format!("podman exec ping: {e}"))?;

        Ok(output.status.success())
    }

    /// Execute a command in a container and return the output.
    pub fn exec(&self, container: Container, cmd: &[&str]) -> Result<Output, String> {
        let container_id = match container {
            Container::Server => self.server_id.as_ref(),
            Container::Client => self.client_id.as_ref(),
        }.ok_or("container not started")?;

        let mut args = vec!["exec", container_id.as_str()];
        args.extend(cmd);

        Command::new("podman")
            .args(&args)
            .output()
            .map_err(|e| format!("podman exec: {e}"))
    }

    /// Get container logs.
    pub fn logs(&self, container: Container) -> Result<String, String> {
        let container_id = match container {
            Container::Server => self.server_id.as_ref(),
            Container::Client => self.client_id.as_ref(),
        }.ok_or("container not started")?;

        let output = Command::new("podman")
            .args(["logs", container_id])
            .output()
            .map_err(|e| format!("podman logs: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(format!("{stdout}\n{stderr}"))
    }

    fn cleanup(&mut self) {
        if let Some(id) = self.client_id.take() {
            let _ = Command::new("podman").args(["rm", "-f", &id]).output();
        }
        if let Some(id) = self.server_id.take() {
            let _ = Command::new("podman").args(["rm", "-f", &id]).output();
        }
        let _ = Command::new("podman").args(["volume", "rm", "-f", &self.volume_name]).output();
        let _ = Command::new("podman").args(["network", "rm", "-f", &self.network_name]).output();
    }
}

impl Drop for PodmanOrchestrator {
    fn drop(&mut self) {
        self.cleanup();
    }
}
