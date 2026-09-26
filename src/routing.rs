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

use std::{
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    path::Path,
};

use ipnet::Ipv4Net;

/// Default fwmark value for VPN transport sockets (matches WireGuard convention).
pub const DEFAULT_FWMARK: u32 = 51820;

/// A network interface address expressed as an IPv4 CIDR (e.g. `"192.168.1.20/24"`).
///
/// This is the vendor-neutral input to [`lan_prefixes_to_exclude`]; real
/// interface discovery is wrapped behind [`InterfaceEnumerator`] so the prefix
/// computation can be unit-tested without network IO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceCidr(pub String);

/// Resolves a resource hostname to destination addresses.
pub trait ResourceResolver {
    /// Resolve `host`, returning all addresses known by the resolver.
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// Production resolver backed by the operating system resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResourceResolver;

impl ResourceResolver for SystemResourceResolver {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        (host, 0)
            .to_socket_addrs()
            .map(|addresses| addresses.map(|address| address.ip()).collect())
    }
}

/// Normalize and validate one resource entry.
pub fn normalize_resource(resource: &str) -> anyhow::Result<String> {
    let normalized = resource.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.contains(char::is_whitespace) || normalized.contains(['*', '/']) {
        anyhow::bail!("invalid resource '{resource}': expected a hostname or IPv4 address");
    }
    if let Ok(address) = normalized.parse::<IpAddr>() {
        if address.is_ipv6() {
            anyhow::bail!("resource '{resource}' is IPv6, but the client tunnel supports IPv4 resources only");
        }
    } else if normalized.contains(':') {
        anyhow::bail!("invalid resource '{resource}': expected a hostname or IPv4 address");
    }
    Ok(normalized)
}

/// Resolve configured resources to unique IPv4 route destinations.
pub fn resolve_resource_ips(resources: &[String], resolver: &impl ResourceResolver) -> anyhow::Result<Vec<Ipv4Addr>> {
    let mut normalized_resources = Vec::new();
    for resource in resources {
        let normalized = normalize_resource(resource)?;
        if !normalized_resources.contains(&normalized) {
            normalized_resources.push(normalized);
        }
    }

    let mut addresses = Vec::new();
    for resource in normalized_resources {
        let resolved = if let Ok(address) = resource.parse::<Ipv4Addr>() {
            vec![IpAddr::V4(address)]
        } else {
            resolver
                .resolve(&resource)
                .map_err(|error| anyhow::anyhow!("failed to resolve resource '{resource}': {error}"))?
        };
        let mut found_ipv4 = false;
        for address in resolved {
            let IpAddr::V4(address) = address else { continue };
            found_ipv4 = true;
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        if !found_ipv4 {
            anyhow::bail!("resource '{resource}' resolved without an IPv4 address");
        }
    }
    Ok(addresses)
}

/// Discovers the active network interfaces' IPv4 CIDRs.
///
/// Wrapped as a trait so callers can inject a deterministic fixture in tests
/// while production uses [`SystemInterfaceEnumerator`].
pub trait InterfaceEnumerator {
    /// Return the IPv4 CIDRs assigned to active (up, non-loopback) interfaces.
    fn enumerate(&self) -> Vec<InterfaceCidr>;
}

/// Compute the RFC1918 local-LAN network prefixes to exclude from the tunnel.
///
/// Pure and IO-free. For each interface CIDR:
/// - parses it as IPv4 (IPv6 and malformed entries are skipped),
/// - keeps only RFC1918 (`10/8`, `172.16/12`, `192.168/16`) addresses,
/// - reduces it to its network prefix (e.g. `192.168.1.20/24` → `192.168.1.0/24`),
/// - drops any prefix present in `skip` (e.g. the tunnel's own subnet).
///
/// The result is deduplicated and stable in first-seen order.
pub fn lan_prefixes_to_exclude(interfaces: &[InterfaceCidr], skip: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for iface in interfaces {
        let Ok(net) = iface.0.parse::<Ipv4Net>() else {
            continue;
        };
        if !net.addr().is_private() {
            continue;
        }
        let prefix = net.trunc().to_string();
        if skip.contains(&prefix) || out.contains(&prefix) {
            continue;
        }
        out.push(prefix);
    }
    out
}

/// Compute the effective excluded-CIDR set for the tunnel.
///
/// Merges the user's explicit `excluded_ips` with the auto-detected RFC1918
/// LAN prefixes (split-tunnel courtesy, the default). When `full_tunnel` is
/// `true`, the LAN prefixes are NOT added, restoring strict full-tunnel capture
/// of LAN traffic. `skip` lists prefixes that must never be auto-excluded (the
/// tunnel's own subnet).
pub fn compute_excluded_ips(user_excluded: &[String], interfaces: &[InterfaceCidr], skip: &[String], full_tunnel: bool) -> Vec<String> {
    let mut out: Vec<String> = user_excluded.to_vec();
    if full_tunnel {
        return out;
    }
    for prefix in lan_prefixes_to_exclude(interfaces, skip) {
        if !out.contains(&prefix) {
            out.push(prefix);
        }
    }
    out
}

/// Default path for the routing hook script.
pub const DEFAULT_ROUTE_HOOK_SCRIPT: &str = "/usr/local/bin/prrr-route";

/// Runtime state directory for env file and routing state.
const STATE_DIR: &str = "/run/prrr";

/// Environment file path written by the binary for the hook script.
const ENV_FILE: &str = "/run/prrr/env";

/// Production [`InterfaceEnumerator`] backed by the OS interface table.
///
/// Lists IPv4 CIDRs of up, non-loopback interfaces via `if-addrs`. On failure
/// it returns an empty list so the tunnel still comes up (degrade, don't fail).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemInterfaceEnumerator;

impl InterfaceEnumerator for SystemInterfaceEnumerator {
    fn enumerate(&self) -> Vec<InterfaceCidr> {
        let Ok(addrs) = if_addrs::get_if_addrs() else {
            tracing::warn!("interface enumeration failed; skipping LAN auto-exclusion");
            return Vec::new();
        };
        addrs
            .into_iter()
            .filter(|iface| !iface.is_loopback())
            .filter_map(|iface| match iface.addr {
                if_addrs::IfAddr::V4(v4) => Some(InterfaceCidr(format!("{}/{}", v4.ip, v4.prefixlen))),
                if_addrs::IfAddr::V6(_) => None,
            })
            .collect()
    }
}

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
    /// Exact IPv4 destinations resolved from configured resources.
    pub resource_ips: Vec<Ipv4Addr>,
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

        std::fs::write(ENV_FILE, self.render_env())
    }

    fn render_env(&self) -> String {
        let dns = self.params.dns_servers.join(" ");
        let allowed = self.params.allowed_ips.join(" ");
        let excluded = self.params.excluded_ips.join(" ");
        let resource_ips = self
            .params
            .resource_ips
            .iter()
            .map(Ipv4Addr::to_string)
            .collect::<Vec<_>>()
            .join(" ");

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
PRRR_RESOURCE_IPS=\"{resource_ips}\"
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
            resource_ips = resource_ips,
            fwmark = self.params.fwmark,
        );

        content
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

    // FRD: specs/frds/FRD-resource-routing.md
    struct FixtureResolver {
        answers: std::collections::HashMap<String, Vec<IpAddr>>,
    }

    impl ResourceResolver for FixtureResolver {
        fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
            self.answers
                .get(host)
                .cloned()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "fixture host missing"))
        }
    }

    #[test]
    fn resources_resolve_to_unique_ipv4_addresses_in_first_seen_order() {
        let resolver = FixtureResolver {
            answers: [
                ("chatgpt.com".to_string(), vec!["203.0.113.10".parse().expect("ip")]),
                (
                    "youtube.com".to_string(),
                    vec!["203.0.113.10".parse().expect("ip"), "203.0.113.11".parse().expect("ip")],
                ),
            ]
            .into_iter()
            .collect(),
        };
        let got = resolve_resource_ips(&["chatgpt.com".to_string(), "youtube.com".to_string()], &resolver).expect("resolve");
        assert_eq!(
            got,
            vec![
                "203.0.113.10".parse::<Ipv4Addr>().expect("ip"),
                "203.0.113.11".parse::<Ipv4Addr>().expect("ip")
            ]
        );
    }

    #[test]
    fn ipv6_only_resource_is_rejected() {
        let resolver = FixtureResolver {
            answers: [("ipv6.example".to_string(), vec!["2001:db8::1".parse().expect("ip")])]
                .into_iter()
                .collect(),
        };
        let error = resolve_resource_ips(&["ipv6.example".to_string()], &resolver).expect_err("IPv6-only resource must fail");
        assert!(error.to_string().contains("ipv6.example"));
    }

    #[test]
    fn unresolved_resource_reports_hostname() {
        let resolver = FixtureResolver {
            answers: std::collections::HashMap::new(),
        };
        let error = resolve_resource_ips(&["missing.example".to_string()], &resolver).expect_err("missing resource must fail");
        assert!(error.to_string().contains("missing.example"));
    }

    #[test]
    fn resource_validation_rejects_wildcards_and_cidrs() {
        for resource in ["*.example.com", "example.com/path"] {
            let error = normalize_resource(resource).expect_err("invalid resource must fail");
            assert!(error.to_string().contains("invalid resource"));
        }
    }

    // FRD: specs/frds/FRD-001-local-lan-auto-exclusion.md

    /// Tunnel's own subnet — must never be auto-excluded (stressor 9).
    const TUN_SUBNET: &str = "10.66.66.0/24";

    fn cidrs(items: &[&str]) -> Vec<InterfaceCidr> {
        items.iter().map(|s| InterfaceCidr(s.to_string())).collect()
    }

    #[test]
    fn lan_exclude_wifi_slash24_yields_network_prefix() {
        let got = lan_prefixes_to_exclude(&cidrs(&["192.168.1.20/24"]), &[]);
        assert_eq!(got, vec!["192.168.1.0/24".to_string()]);
    }

    #[test]
    fn lan_exclude_multiple_interfaces_deduped() {
        let got = lan_prefixes_to_exclude(&cidrs(&["192.168.1.20/24", "172.16.5.9/16", "192.168.1.30/24"]), &[]);
        assert_eq!(got, vec!["192.168.1.0/24".to_string(), "172.16.0.0/16".to_string()]);
    }

    #[test]
    fn lan_exclude_skips_non_rfc1918() {
        // CGNAT (100.64/10) and link-local (169.254/16) are not LAN.
        let got = lan_prefixes_to_exclude(&cidrs(&["100.64.0.5/10", "169.254.1.1/16", "8.8.8.8/32"]), &[]);
        assert!(got.is_empty(), "non-RFC1918 must not be excluded, got {got:?}");
    }

    #[test]
    fn lan_exclude_skips_ipv6_and_malformed() {
        let got = lan_prefixes_to_exclude(&cidrs(&["fe80::1/64", "not-a-cidr", "192.168.0.7/24"]), &[]);
        assert_eq!(got, vec!["192.168.0.0/24".to_string()]);
    }

    #[test]
    fn lan_exclude_honors_skip_list() {
        // The tunnel subnet must never be excluded even though it is RFC1918.
        let got = lan_prefixes_to_exclude(&cidrs(&["10.66.66.2/24"]), &[TUN_SUBNET.to_string()]);
        assert!(got.is_empty(), "tunnel subnet must be skipped, got {got:?}");
    }

    #[test]
    fn lan_exclude_all_rfc1918_block_sizes() {
        let got = lan_prefixes_to_exclude(&cidrs(&["10.1.2.3/8", "172.20.30.40/12", "192.168.50.60/16"]), &[]);
        assert_eq!(
            got,
            vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string(), "192.168.0.0/16".to_string()]
        );
    }

    #[test]
    fn compute_excluded_default_merges_user_and_lan() {
        let got = compute_excluded_ips(&["1.2.3.0/24".to_string()], &cidrs(&["192.168.1.5/24"]), &[], false);
        assert_eq!(got, vec!["1.2.3.0/24".to_string(), "192.168.1.0/24".to_string()]);
    }

    #[test]
    fn compute_excluded_strict_full_tunnel_omits_lan() {
        // full_tunnel = true: LAN is captured by the tunnel, not excluded.
        let got = compute_excluded_ips(&[], &cidrs(&["192.168.1.5/24"]), &[], true);
        assert!(got.is_empty(), "strict full tunnel must not auto-exclude LAN, got {got:?}");
    }

    #[test]
    fn compute_excluded_no_duplicate_when_user_already_listed_lan() {
        let got = compute_excluded_ips(&["192.168.1.0/24".to_string()], &cidrs(&["192.168.1.5/24"]), &[], false);
        assert_eq!(got, vec!["192.168.1.0/24".to_string()]);
    }

    /// Stub LAN peer e2e (route-computation surface): a LAN-destined prefix is
    /// excluded by default (stays on the LAN) and captured when strict.
    #[test]
    fn stub_lan_peer_default_excluded_strict_captured() {
        let lan_iface = cidrs(&["192.168.1.50/24"]);
        let lan_peer_prefix = "192.168.1.0/24".to_string();

        let default_set = compute_excluded_ips(&[], &lan_iface, &[TUN_SUBNET.to_string()], false);
        assert!(default_set.contains(&lan_peer_prefix), "default: LAN peer must be off-tunnel");

        let strict_set = compute_excluded_ips(&[], &lan_iface, &[TUN_SUBNET.to_string()], true);
        assert!(
            !strict_set.contains(&lan_peer_prefix),
            "strict: LAN peer must be captured by tunnel"
        );
    }

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
            resource_ips: vec![],
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
    fn route_params_env_contains_resource_ips() {
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
            resource_ips: vec![Ipv4Addr::new(203, 0, 113, 10)],
            fwmark: DEFAULT_FWMARK,
        };
        let manager = RouteManager::new(params, "/nonexistent/script".to_string());
        assert!(manager.render_env().contains("PRRR_RESOURCE_IPS=\"203.0.113.10\""));
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
            resource_ips: vec![],
            fwmark: DEFAULT_FWMARK,
        };
        let mut mgr = RouteManager::new(params, "/nonexistent/script".to_string());
        // Calling down() when not up should be a no-op
        mgr.down();
        mgr.down();
    }
}
