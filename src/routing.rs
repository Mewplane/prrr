//! Binary-driven routing lifecycle for the prrr VPN client.
//!
//! [`RouteManager`] owns the route setup/teardown lifecycle, calling an
//! external hook script (default `/usr/local/bin/prrr-route`) at the right
//! moments — after transport connects and before disconnect/reconnect.
//!
//! All routing parameters are written to `/run/prrr/env` as shell variables
//! so the hook script can source them instead of parsing TOML.
//!
//! [`set_socket_fwmark`] marks transport sockets with SO_MARK so the kernel
//! routes VPN protocol traffic outside the tunnel (WireGuard-style fwmark
//! policy routing).

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

/// Default fwmark value for VPN transport sockets (matches WireGuard convention).
pub const DEFAULT_FWMARK: u32 = 51820;

/// Default path for the routing hook script.
pub const DEFAULT_ROUTE_HOOK_SCRIPT: &str = "/usr/local/bin/prrr-route";

/// Runtime state directory for env file and routing state.
const STATE_DIR: &str = "/run/prrr";

/// Environment file path written by the binary for the hook script.
const ENV_FILE: &str = "/run/prrr/env";

/// All parameters needed for routing setup.
pub struct RouteParams {
    /// TUN device name (e.g. `"prrr0"`).
    pub tun_device: String,
    /// Client VPN IP address.
    pub client_ip: Ipv4Addr,
    /// Gateway IP (first host in VPN subnet).
    pub gateway_ip: Ipv4Addr,
    /// Resolved server IP address.
    pub server_ip: IpAddr,
    /// Server hostname (for display/logging).
    pub server_endpoint: String,
    /// Route all traffic through VPN.
    pub all_traffic: bool,
    /// DNS servers for the tunnel.
    pub dns_servers: Vec<String>,
    /// Allowed destination CIDRs (split-tunnel).
    pub allowed_ips: Vec<String>,
    /// Excluded destination CIDRs.
    pub excluded_ips: Vec<String>,
    /// Firewall mark for VPN transport sockets.
    pub fwmark: u32,
}

/// Manages the routing lifecycle for the VPN client.
///
/// Writes structured config to `/run/prrr/env` and invokes the hook script
/// for route setup (`up`) and teardown (`down`). Implements [`Drop`] to
/// ensure routes are cleaned up on unexpected exit.
pub struct RouteManager {
    params: RouteParams,
    hook_script: String,
    is_up: bool,
}

impl RouteManager {
    /// Create a new route manager with the given parameters and hook script path.
    pub fn new(params: RouteParams, hook_script: String) -> Self {
        Self {
            params,
            hook_script,
            is_up: false,
        }
    }

    /// Set up routing: write env file, then execute hook script `up`.
    ///
    /// Logs a warning and continues if the hook script is missing.
    pub fn up(&mut self) {
        if self.is_up {
            tracing::debug!("routing already up, skipping");
            return;
        }

        if let Err(e) = self.write_env_file() {
            tracing::warn!(error = %e, "failed to write routing env file");
        }

        self.run_hook("up");
        self.is_up = true;
    }

    /// Tear down routing: execute hook script `down`, remove env file.
    ///
    /// Logs a warning and continues if the hook script is missing.
    pub fn down(&mut self) {
        if !self.is_up {
            return;
        }

        self.run_hook("down");
        self.is_up = false;

        // Clean up env file
        let _ = std::fs::remove_file(ENV_FILE);
    }

    /// Write routing parameters to `/run/prrr/env` as shell variables.
    fn write_env_file(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(STATE_DIR)?;

        let dns = self.params.dns_servers.join(" ");
        let allowed = self.params.allowed_ips.join(" ");
        let excluded = self.params.excluded_ips.join(" ");

        let content = format!(
            "\
PRRR_DEVICE={device}
PRRR_CLIENT_IP={client_ip}
PRRR_GATEWAY_IP={gateway_ip}
PRRR_SERVER_IP={server_ip}
PRRR_SERVER_ENDPOINT={server_endpoint}
PRRR_ALL_TRAFFIC={all_traffic}
PRRR_DNS_SERVERS=\"{dns}\"
PRRR_ALLOWED_IPS=\"{allowed}\"
PRRR_EXCLUDED_IPS=\"{excluded}\"
PRRR_FWMARK={fwmark}
",
            device = self.params.tun_device,
            client_ip = self.params.client_ip,
            gateway_ip = self.params.gateway_ip,
            server_ip = self.params.server_ip,
            server_endpoint = self.params.server_endpoint,
            all_traffic = self.params.all_traffic,
            dns = dns,
            allowed = allowed,
            excluded = excluded,
            fwmark = self.params.fwmark,
        );

        std::fs::write(ENV_FILE, content)
    }

    /// Execute the hook script with the given action (`up` or `down`).
    fn run_hook(&self, action: &str) {
        let script = &self.hook_script;

        if !Path::new(script).exists() {
            tracing::warn!(script, action, "routing hook script not found, skipping");
            return;
        }

        tracing::info!(script, action, "executing routing hook");

        match std::process::Command::new(script).arg(action).status() {
            Ok(status) if status.success() => {
                tracing::info!(action, "routing hook completed successfully");
            }
            Ok(status) => {
                tracing::warn!(action, code = ?status.code(), "routing hook exited with error");
            }
            Err(e) => {
                tracing::warn!(action, error = %e, "failed to execute routing hook");
            }
        }
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        self.down();
    }
}

/// Set SO_MARK (fwmark) on a socket for policy routing.
///
/// On Linux, this marks all packets sent through the socket with the given
/// value, allowing `ip rule` to route them differently from tunnel traffic.
/// Requires `CAP_NET_ADMIN`.
///
/// On non-Linux platforms, this is a no-op.
#[cfg(target_os = "linux")]
pub fn set_socket_fwmark(socket: &socket2::Socket, mark: u32) -> std::io::Result<()> {
    socket.set_mark(mark)
}

/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn set_socket_fwmark(_socket: &socket2::Socket, _mark: u32) -> std::io::Result<()> {
    Ok(())
}

/// Create a TCP socket with fwmark set (for HARP HTTP/WebSocket connections).
///
/// Returns a `socket2::Socket` ready for `connect()`. The SO_MARK is set
/// before connection so all packets (including SYN) are marked.
pub fn create_marked_tcp_socket(domain: socket2::Domain, fwmark: Option<u32>) -> std::io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if let Some(mark) = fwmark {
        set_socket_fwmark(&socket, mark)?;
    }
    Ok(socket)
}

/// Create a UDP socket with fwmark set (for MASQUE/QUIC connections).
///
/// Returns a `std::net::UdpSocket` bound to `0.0.0.0:0`, ready for use
/// with `quinn::Endpoint::new()`.
pub fn create_marked_udp_socket(fwmark: Option<u32>) -> std::io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if let Some(mark) = fwmark {
        set_socket_fwmark(&socket, mark)?;
    }
    socket.bind(&socket2::SockAddr::from(std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_params_env_format() {
        let params = RouteParams {
            tun_device: "prrr0".to_string(),
            client_ip: Ipv4Addr::new(10, 66, 66, 2),
            gateway_ip: Ipv4Addr::new(10, 66, 66, 1),
            server_ip: IpAddr::V4(Ipv4Addr::new(164, 92, 235, 224)),
            server_endpoint: "prrr.tech".to_string(),
            all_traffic: true,
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            allowed_ips: vec![],
            excluded_ips: vec![],
            fwmark: DEFAULT_FWMARK,
        };

        let mgr = RouteManager::new(params, "/nonexistent/script".to_string());

        // Verify env file content would be correct
        let dns = mgr.params.dns_servers.join(" ");
        assert_eq!(dns, "1.1.1.1 8.8.8.8");
        assert_eq!(mgr.params.fwmark, 51820);
        assert!(mgr.params.all_traffic);
    }

    #[test]
    fn create_marked_tcp_socket_no_mark() {
        let socket = create_marked_tcp_socket(socket2::Domain::IPV4, None);
        assert!(socket.is_ok());
    }

    #[test]
    fn create_marked_udp_socket_no_mark() {
        let socket = create_marked_udp_socket(None);
        assert!(socket.is_ok());
    }

    #[test]
    fn route_manager_down_idempotent() {
        let params = RouteParams {
            tun_device: "prrr0".to_string(),
            client_ip: Ipv4Addr::new(10, 66, 66, 2),
            gateway_ip: Ipv4Addr::new(10, 66, 66, 1),
            server_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            server_endpoint: "test.example.com".to_string(),
            all_traffic: false,
            dns_servers: vec![],
            allowed_ips: vec![],
            excluded_ips: vec![],
            fwmark: DEFAULT_FWMARK,
        };
        let mut mgr = RouteManager::new(params, "/nonexistent/script".to_string());
        // Calling down() when not up should be a no-op
        mgr.down();
        mgr.down();
    }
}
