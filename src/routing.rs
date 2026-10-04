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
    path::{Path, PathBuf},
    sync::Arc,
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

/// Number of consecutive observation cycles a resolved resource IP stays in
/// the active route set after it stops appearing in fresh DNS answers.
///
/// CDN front-ends rotate A records per query; a zero-window replace would
/// pull routes out from under connections that just started, while a pure
/// union would accumulate addresses forever. The grace window bounds the set
/// while tolerating normal rotation.
/// Defaults to 8 one-minute refresh rounds (~8 minutes), sized so that
/// per-query-rotating CDN answer pools are covered in steady state.
pub const RESOURCE_RETAIN_CYCLES: u64 = 8;

/// Upper bound on simultaneously routed resource addresses. Answer-order
/// tails beyond the cap are evicted; re-sighting an evicted address re-admits
/// it. Bounds route-table growth for large rotating pools.
pub const RESOURCE_MAX_ADDRESSES: usize = 256;

/// Tracks which resolved resource IPs are currently routed.
///
/// [`Self::observe`] folds one fresh resolution round into the active set:
/// newly seen addresses first (in answer order), then previously active
/// addresses last seen within the retention window. Addresses that stop being
/// seen leave the set once they fall out of the window, so the route table
/// cannot grow without bound on fast-rotating CDNs.
#[derive(Debug)]
pub struct ResourceTracker {
    cycle: u64,
    last_seen: std::collections::HashMap<Ipv4Addr, u64>,
    active: Vec<Ipv4Addr>,
    retain_cycles: u64,
    max_active: usize,
}

impl Default for ResourceTracker {
    fn default() -> Self {
        Self {
            cycle: 0,
            last_seen: std::collections::HashMap::new(),
            active: Vec::new(),
            retain_cycles: RESOURCE_RETAIN_CYCLES,
            max_active: RESOURCE_MAX_ADDRESSES,
        }
    }
}

impl ResourceTracker {
    /// Tracker with an explicit retention window and active-set cap (black-box
    /// tests; production uses [`Self::default`]).
    fn with_limits(retain_cycles: u64, max_active: usize) -> Self {
        Self {
            cycle: 0,
            last_seen: std::collections::HashMap::new(),
            active: Vec::new(),
            retain_cycles,
            max_active,
        }
    }

    /// Record one fresh DNS answer (exactly what the resolver returned) and
    /// return the new active set.
    ///
    /// Addresses in the answer are sighted this round; previously active
    /// addresses within the retention window are kept behind them; addresses
    /// whose absence spans `RESOURCE_RETAIN_CYCLES` consecutive answers are
    /// dropped for good.
    pub fn observe(&mut self, answer: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
        self.cycle += 1;
        for address in answer {
            self.last_seen.insert(*address, self.cycle);
        }

        let mut out: Vec<Ipv4Addr> = Vec::new();
        for address in answer {
            if !out.contains(address) {
                out.push(*address);
            }
        }
        for address in &self.active {
            let recently_seen = self
                .last_seen
                .get(address)
                .is_some_and(|seen| self.cycle - *seen < self.retain_cycles);
            if recently_seen && !out.contains(address) {
                out.push(*address);
            }
        }
        out.truncate(self.max_active);
        let kept = out.clone();
        self.last_seen
            .retain(|address, seen| kept.contains(address) && self.cycle - *seen < self.retain_cycles);

        self.active = kept.clone();
        kept
    }
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
pub fn resolve_resource_ips(resources: &[String], resolver: &dyn ResourceResolver) -> anyhow::Result<Vec<Ipv4Addr>> {
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
    /// Normalized resource hostnames (or IPv4 literals) kept re-resolved while running.
    pub resources: Vec<String>,
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
    tracker: ResourceTracker,
    env_file: PathBuf,
    pending_stale: Vec<Ipv4Addr>,
    resolver: Arc<dyn ResourceResolver + Send + Sync>,
    /// Whether the tunnel's DNS servers may currently be handed to the system
    /// resolver. Starts open; a failed [`crate::dns_probe`] closes it so a
    /// broken tunnel never starves host resolution. The tunnel `/32` pins stay
    /// installed either way — they define the path the probe measures.
    /// BUG: specs/bugs/BUG-network-manager-tun-address-loss.md
    dns_gate_open: bool,
    /// The subset of `[interface].dns` currently handed to the system resolver.
    /// Starts as the whole configured list and narrows to the responders that
    /// actually answered through the tunnel, so one unreachable address (or a
    /// server the probe cannot measure being the only one left) cannot make the
    /// host inherit a resolver that never replies.
    /// BUG: specs/bugs/BUG-tunnel-dns-single-probe-target.md
    dns_advertise: Vec<String>,
}

impl RouteManager {
    /// Create a new route manager with the given parameters and hook script path.
    pub fn new(params: RouteParams, hook_script: String) -> Self {
        let mut tracker = ResourceTracker::default();
        tracker.observe(&params.resource_ips);
        let dns_advertise = params.dns_servers.clone();
        Self {
            params,
            dns_advertise,
            hook_script,
            is_up: false,
            tracker,
            env_file: PathBuf::from(ENV_FILE),
            pending_stale: Vec::new(),
            resolver: Arc::new(SystemResourceResolver),
            dns_gate_open: true,
        }
    }

    /// Point the env file at an alternate path (black-box tests; production
    /// keeps `/run/prrr/env`). The hook receives the location via
    /// `PRRR_ENV_FILE`, which the hook honors by design.
    #[must_use]
    pub fn with_env_file(mut self, env_file: impl Into<PathBuf>) -> Self {
        self.env_file = env_file.into();
        self
    }

    /// Override the resource retention window (black-box tests).
    #[must_use]
    pub fn with_resource_retention(mut self, retain_cycles: u64) -> Self {
        let max_active = self.tracker.max_active;
        let seeded = self.tracker.observe(&[]);
        self.tracker = ResourceTracker::with_limits(retain_cycles, max_active);
        self.tracker.observe(&seeded);
        self
    }

    /// Override the resolver used for background refresh rounds (tests).
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn ResourceResolver + Send + Sync>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Hostnames and resolver handle to feed a background re-resolution
    /// round, or `None` when no hostname resources are configured.
    pub fn resource_refresh_inputs(&self) -> Option<(Vec<String>, Arc<dyn ResourceResolver + Send + Sync>)> {
        if self.params.resources.is_empty() {
            return None;
        }
        Some((self.params.resources.clone(), self.resolver.clone()))
    }

    /// Which resolver addresses the caller must probe to decide the DNS gate.
    /// Non-empty exactly when this configuration makes the hook pin DNS servers
    /// through the tunnel: an IPv4 server plus a mode that installs tunnel
    /// routes. IPv6 servers are never pinned (the TUN is IPv4-only).
    ///
    /// Every configured server is a target, not just the first: a deployment
    /// whose first address is unreachable for this peer (anycast policy, the
    /// upstream filtering UDP/53 to it) must not be judged dead while a later
    /// configured responder still answers through the tunnel.
    /// BUG: specs/bugs/BUG-tunnel-dns-single-probe-target.md
    #[must_use]
    pub fn dns_probe_targets(&self) -> Vec<Ipv4Addr> {
        if !self.params.all_traffic && self.params.resource_ips.is_empty() {
            return Vec::new();
        }
        self.pinned_ipv4_dns()
    }

    /// Resource hostnames the tunnel resolver should be scoped to.
    ///
    /// In split mode the tunnel only carries these names' traffic, so only
    /// these names should be resolved through it: every other name leaves over
    /// the host's own path anyway, and asking the tunnel to arbitrate it turns a
    /// degraded tunnel into a host-wide resolution outage. Literal addresses
    /// need no name-based routing and are left out.
    /// BUG: specs/bugs/BUG-split-mode-dns-catchall-hijacks-host-resolver.md
    #[must_use]
    pub fn dns_resource_domains(&self) -> Vec<String> {
        self.params
            .resources
            .iter()
            .map(|resource| resource.trim())
            .filter(|resource| !resource.is_empty() && !resource.contains('/') && resource.parse::<IpAddr>().is_err())
            .map(str::to_string)
            .collect()
    }

    /// The configured DNS servers that the hook pins through the tunnel, i.e.
    /// the addresses a probe can actually judge. Names and IPv6 servers are
    /// advertised but never measured, so they are never withdrawn.
    fn pinned_ipv4_dns(&self) -> Vec<Ipv4Addr> {
        self.params
            .dns_servers
            .iter()
            .filter_map(|server| server.parse::<IpAddr>().ok())
            .filter_map(|addr| match addr {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect()
    }

    /// The advertisement this configuration would hand the system resolver if
    /// exactly `alive` responders answered: every configured server except the
    /// pinned IPv4 ones that stayed silent.
    fn advertisement_for(&self, alive: &[Ipv4Addr]) -> Vec<String> {
        let measured: Vec<Ipv4Addr> = if self.dns_probe_targets().is_empty() {
            self.params
                .dns_servers
                .iter()
                .filter_map(|server| server.parse::<IpAddr>().ok())
                .filter_map(|addr| match addr {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                })
                .collect()
        } else {
            self.dns_probe_targets()
        };
        self.params
            .dns_servers
            .iter()
            .filter(|server| !matches!(server.parse::<IpAddr>(), Ok(IpAddr::V4(v4)) if measured.contains(&v4) && !alive.contains(&v4)))
            .cloned()
            .collect()
    }

    /// Record which pinned DNS responders answered, returning `true` when the
    /// published routing state changed. A change rewrites the env file and
    /// re-runs the hook, so the system resolver is handed the live tunnel
    /// resolvers, the host's own resolvers (when nothing answered), or a
    /// narrowed advertisement within one probe round. Unchanged observations
    /// are free, so a healthy tunnel sees no hook churn every interval.
    ///
    /// The gate opens on *any* answering responder: withdrawing DNS because the
    /// first configured address is silent would discard a tunnel that resolves
    /// perfectly well through a later one.
    /// BUG: specs/bugs/BUG-tunnel-dns-single-probe-target.md
    pub fn observe_dns_health(&mut self, alive: &[Ipv4Addr]) -> bool {
        let want_open = !alive.is_empty();
        let want_advertise = if want_open {
            self.advertisement_for(alive)
        } else {
            // Closed means nothing is advertised at all, so the list the hook
            // would use is irrelevant until the gate opens again.
            self.dns_advertise.clone()
        };
        if want_open == self.dns_gate_open && want_advertise == self.dns_advertise {
            return false;
        }
        self.dns_gate_open = want_open;
        self.dns_advertise = want_advertise.clone();
        if want_open {
            tracing::info!(
                advertised = %want_advertise.join(" "),
                "tunnel DNS responder alive: advertising the responding tunnel resolvers"
            );
        } else {
            tracing::warn!("no tunnel DNS responder answered: keeping the host's own resolver instead of a black hole");
        }
        if self.is_up {
            if let Err(e) = self.write_env_file() {
                tracing::warn!(error = %e, "failed to rewrite routing env file after DNS gate change");
            }
            self.run_hook("up");
        }
        true
    }

    /// Current DNS gate state (tests, `doctor`).
    #[must_use]
    pub fn dns_gate_open(&self) -> bool {
        self.dns_gate_open
    }

    /// Fold a fresh resolution round into the routed resource set.
    ///
    /// When the active set (see [`ResourceTracker`]) changed and routing is
    /// up, the env file is rewritten — now also carrying the IPs that aged
    /// out of the retention window as `PRRR_STALE_RESOURCE_IPS` — and the
    /// hook's idempotent `up` runs again. While down, only the pending set
    /// updates; the next `up` installs it.
    pub fn apply_resource_ips(&mut self, fresh: Vec<Ipv4Addr>) {
        let active = self.tracker.observe(&fresh);
        if active == self.params.resource_ips {
            return;
        }
        let removed: Vec<Ipv4Addr> = self
            .params
            .resource_ips
            .iter()
            .copied()
            .filter(|address| !active.contains(address))
            .collect();
        self.params.resource_ips = active;
        if !self.is_up {
            return;
        }
        for address in removed {
            if !self.pending_stale.contains(&address) {
                self.pending_stale.push(address);
            }
        }
        if let Err(e) = self.write_env_file() {
            tracing::warn!(error = %e, "failed to write routing env file");
        }
        self.run_hook("up");
        self.pending_stale.clear();
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
        self.pending_stale.clear();

        // Clean up env file
        let _ = std::fs::remove_file(&self.env_file);
    }

    /// Write routing parameters to `/run/prrr/env` as shell variables.
    fn write_env_file(&self) -> std::io::Result<()> {
        if let Some(parent) = self.env_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&self.env_file, self.render_env())
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
        let stale_resource_ips = self.pending_stale.iter().map(Ipv4Addr::to_string).collect::<Vec<_>>().join(" ");

        let content = format!(
            "\
PRRR_DEVICE={device}
PRRR_CLIENT_IP={client_ip}
PRRR_GATEWAY_IP={gateway_ip}
PRRR_SERVER_IP={server_ip}
PRRR_SERVER_ENDPOINT={server_endpoint}
PRRR_ALL_TRAFFIC={all_traffic}
PRRR_DNS_SERVERS=\"{dns}\"
PRRR_DNS_ADVERTISE_SERVERS=\"{advertise}\"
PRRR_RESOURCE_DOMAINS=\"{resource_domains}\"
PRRR_ALLOWED_IPS=\"{allowed}\"
PRRR_EXCLUDED_IPS=\"{excluded}\"
PRRR_RESOURCE_IPS=\"{resource_ips}\"
PRRR_STALE_RESOURCE_IPS=\"{stale_resource_ips}\"
PRRR_DNS_GATE={dns_gate}
PRRR_FWMARK={fwmark}
",
            device = self.params.tun_device,
            client_ip = self.params.client_ip,
            gateway_ip = self.params.gateway_ip,
            server_ip = self.params.server_ip,
            server_endpoint = self.params.server_endpoint,
            all_traffic = self.params.all_traffic,
            dns = dns,
            advertise = self.dns_advertise.join(" "),
            resource_domains = self.dns_resource_domains().join(" "),
            allowed = allowed,
            excluded = excluded,
            resource_ips = resource_ips,
            stale_resource_ips = stale_resource_ips,
            dns_gate = if self.dns_gate_open { "on" } else { "off" },
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

        match std::process::Command::new(script)
            .arg(action)
            .env("PRRR_ENV_FILE", &self.env_file)
            .status()
        {
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

    // FRD: specs/frds/FRD-resource-routing.md
    // BUG: specs/bugs/BUG-resource-ip-staleness.md
    #[test]
    fn resource_tracker_keeps_recently_seen_and_drops_rotated_out_ips() {
        let a = Ipv4Addr::new(203, 0, 113, 1);
        let b = Ipv4Addr::new(203, 0, 113, 2);
        let c = Ipv4Addr::new(203, 0, 113, 3);

        let mut tracker = ResourceTracker::with_limits(3, 64);
        assert_eq!(tracker.observe(&[a, b]), vec![a, b], "first answer is the fresh set");
        assert_eq!(tracker.observe(&[b, c]), vec![b, c, a], "rotated-out peer inside grace window");
        assert_eq!(tracker.observe(&[c]), vec![c, b, a], "one answer without a sighting still retained");
        assert_eq!(tracker.observe(&[c]), vec![c, b], "two answers without a sighting still retained");
        assert_eq!(tracker.observe(&[c]), vec![c], "third absent answer drops the oldest for good");
    }

    #[test]
    fn resource_tracker_deduplicates_fresh_answers() {
        let a = Ipv4Addr::new(203, 0, 113, 1);
        let mut tracker = ResourceTracker::default();
        assert_eq!(tracker.observe(&[a, a, a]), vec![a]);
        assert_eq!(tracker.observe(&[a]), vec![a]);
    }

    #[test]
    fn resource_tracker_caps_active_set_keeping_freshest() {
        let ip = |last| Ipv4Addr::new(203, 0, 113, last);
        let (a, b, c, d, e) = (ip(1), ip(2), ip(3), ip(4), ip(5));

        let mut tracker = ResourceTracker::with_limits(4, 3);
        assert_eq!(
            tracker.observe(&[a, b, c, d]),
            vec![a, b, c],
            "answer order kept, tail over cap evicted"
        );
        assert_eq!(
            tracker.observe(&[e]),
            vec![e, a, b],
            "evicted d never returns; freshest two retained"
        );
        // Re-sighting an evicted address re-admits it.
        assert_eq!(tracker.observe(&[d]), vec![d, e, a]);
    }

    // BUG: specs/bugs/BUG-resource-ip-staleness.md
    #[test]
    fn apply_resource_ips_refreshes_hook_only_while_up_and_only_on_change() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let ip = |last| Ipv4Addr::new(203, 0, 113, last);
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("hook.log");
        let hook = dir.path().join("hook.sh");
        fs::write(
            &hook,
            format!(
                "#!/bin/bash\necho \"action=$1\" >> '{log}'\nwhile IFS= read -r line; do case \"$line\" in PRRR_RESOURCE_IPS=*|PRRR_STALE_RESOURCE_IPS=*) echo \"$line\" >> '{log}';; esac; done < \"$PRRR_ENV_FILE\"\n",
                log = log.display()
            ),
        )
        .expect("write hook");
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).expect("chmod hook");

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
            resources: vec!["chatgpt.com".to_string()],
            resource_ips: vec![ip(1)],
            fwmark: DEFAULT_FWMARK,
        };
        let mut mgr = RouteManager::new(params, hook.display().to_string())
            .with_env_file(dir.path().join("env"))
            .with_resource_retention(3);

        // While routing is down, refresh only updates the set: no hook, no env file.
        mgr.apply_resource_ips(vec![ip(2)]);
        assert!(!log.exists(), "hook must not run while routing is down");
        assert!(!dir.path().join("env").exists(), "env file must not be written while down");

        mgr.up();
        let mut text = fs::read_to_string(&log).expect("hook log");
        assert!(text.contains("action=up"), "{text}");
        assert!(
            text.contains("PRRR_RESOURCE_IPS=\"203.0.113.2 203.0.113.1\""),
            "fresh first, seeded IP still in grace window: {text}"
        );
        assert!(text.contains("PRRR_STALE_RESOURCE_IPS=\"\""), "{text}");

        // Identical resolution result: nothing changed, the hook must stay quiet.
        mgr.apply_resource_ips(vec![ip(2)]);
        text = fs::read_to_string(&log).expect("hook log");
        assert_eq!(text.matches("action=up").count(), 1, "no-change refresh must not re-run the hook");

        // Rotation while up. Timeline of DNS answers (observed rounds):
        // seed [1] = r1; pre-up [2] = r2; no-change [2] = r3; the next answer
        // [3] = r4 drops the seeded IP (absent from r2..r4) as stale, while
        // ip(2) (last seen at r3) stays in the grace window.
        mgr.apply_resource_ips(vec![ip(3)]);
        text = fs::read_to_string(&log).expect("hook log");
        assert_eq!(text.matches("action=up").count(), 2, "changed set must re-run hook");
        assert!(
            text.contains("PRRR_RESOURCE_IPS=\"203.0.113.3 203.0.113.2\"") && text.contains("PRRR_STALE_RESOURCE_IPS=\"203.0.113.1\""),
            "rotated-out IP handed to the hook as stale: {text}"
        );

        // Repeated identical answer: unchanged set, hook stays quiet.
        mgr.apply_resource_ips(vec![ip(3)]);
        text = fs::read_to_string(&log).expect("hook log");
        assert_eq!(text.matches("action=up").count(), 2, "no-change refresh must not re-run the hook");

        // Next rotation ages ip(2) out (absent from the two newest answers).
        mgr.apply_resource_ips(vec![ip(4)]);
        text = fs::read_to_string(&log).expect("hook log");
        assert_eq!(text.matches("action=up").count(), 3, "second rotation must re-run hook");
        assert!(
            text.contains("PRRR_RESOURCE_IPS=\"203.0.113.4 203.0.113.3\"") && text.contains("PRRR_STALE_RESOURCE_IPS=\"203.0.113.2\""),
            "{text}"
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
            resources: vec![],
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
            resources: vec![],
            resource_ips: vec![Ipv4Addr::new(203, 0, 113, 10)],
            fwmark: DEFAULT_FWMARK,
        };
        let manager = RouteManager::new(params, "/nonexistent/script".to_string());
        assert!(manager.render_env().contains("PRRR_RESOURCE_IPS=\"203.0.113.10\""));
    }

    // BUG: specs/bugs/BUG-network-manager-tun-address-loss.md
    /// Params for the DNS-gate tests: the two modes that make the hook pin DNS
    /// servers through the tunnel are `all_traffic` and a non-empty resource set.
    fn gate_params(all_traffic: bool, dns_servers: Vec<String>, resource_ips: Vec<Ipv4Addr>) -> RouteParams {
        RouteParams {
            tun_device: "prrr0".to_string(),
            client_ip: Ipv4Addr::new(10, 66, 66, 2),
            gateway_ip: Ipv4Addr::new(10, 66, 66, 1),
            server_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 79)),
            server_endpoint: "vpn.example".to_string(),
            all_traffic,
            dns_servers,
            allowed_ips: vec![],
            excluded_ips: vec![],
            resources: vec![],
            resource_ips,
            fwmark: DEFAULT_FWMARK,
        }
    }

    #[test]
    fn dns_gate_state_is_published_to_the_hook_env() {
        let mut mgr = RouteManager::new(
            gate_params(true, vec!["1.1.1.1".to_string()], vec![]),
            "/nonexistent/script".to_string(),
        );

        // A start must not black-hole the host: DNS is advertised optimistically
        // and withdrawn by the first failed probe, not the other way round.
        assert!(mgr.dns_gate_open(), "the gate starts open");
        let env = mgr.render_env();
        assert!(env.contains("PRRR_DNS_GATE=on"), "{env}");

        assert!(mgr.observe_dns_health(&[]), "no responder answering is a change");
        let env = mgr.render_env();
        assert!(
            env.contains("PRRR_DNS_GATE=off"),
            "closed gate must withhold the advertisement: {env}"
        );

        assert!(
            mgr.observe_dns_health(&[std::net::Ipv4Addr::new(1, 1, 1, 1)]),
            "a responder answering again is a change"
        );
        assert!(mgr.render_env().contains("PRRR_DNS_GATE=on"));
    }

    #[test]
    fn dns_gate_change_reruns_hook_only_while_up_and_only_on_change() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("hook.log");
        let hook = dir.path().join("hook.sh");
        fs::write(
            &hook,
            format!(
                "#!/bin/bash\necho \"action=$1\" >> '{log}'\nwhile IFS= read -r line; do case \"$line\" in PRRR_DNS_GATE=*) echo \"$line\" >> '{log}';; esac; done < \"$PRRR_ENV_FILE\"\n",
                log = log.display()
            ),
        )
        .expect("write hook");
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).expect("chmod hook");
        let read_log = || fs::read_to_string(&log).unwrap_or_default();

        let responder = Ipv4Addr::new(1, 1, 1, 1);
        let mut mgr = RouteManager::new(gate_params(true, vec!["1.1.1.1".to_string()], vec![]), hook.display().to_string())
            .with_env_file(dir.path().join("env"));

        // Down + an unchanged verdict: nothing to do at all.
        assert!(!mgr.observe_dns_health(&[responder]), "the gate starts open, so this is no change");
        assert!(!log.exists(), "no hook may run while routing is down");

        mgr.up();
        let text = read_log();
        assert_eq!(text.matches("action=up").count(), 1, "{text}");
        assert!(text.contains("PRRR_DNS_GATE=on"), "{text}");

        // Healthy probe: gate already open, so the hook must stay quiet.
        assert!(
            !mgr.observe_dns_health(&[responder]),
            "healthy verdict on an open gate is no change"
        );
        assert_eq!(
            read_log().matches("action=up").count(),
            1,
            "unchanged gate must not re-run the hook"
        );

        // Dead resolver: one hook run that hands resolution back to the host.
        assert!(mgr.observe_dns_health(&[]), "open -> closed is a change");
        let text = read_log();
        assert_eq!(text.matches("action=up").count(), 2, "closed gate must re-run the hook: {text}");
        assert!(text.contains("PRRR_DNS_GATE=off"), "{text}");

        assert!(!mgr.observe_dns_health(&[]), "repeated failure is no change");
        assert_eq!(read_log().matches("action=up").count(), 2, "no hook churn every probe round");

        // Recovery re-advertises without operator action.
        assert!(mgr.observe_dns_health(&[responder]), "closed -> open is a change");
        let text = read_log();
        assert_eq!(text.matches("action=up").count(), 3, "recovery must re-run the hook: {text}");
        assert_eq!(text.matches("PRRR_DNS_GATE=on").count(), 2, "{text}");

        // While down, the gate still tracks the verdict but never touches the hook.
        mgr.down();
        let ups_after_down = read_log().matches("action=up").count();
        assert!(mgr.observe_dns_health(&[]), "state must track verdicts while down too");
        assert!(!mgr.dns_gate_open());
        assert_eq!(
            read_log().matches("action=up").count(),
            ups_after_down,
            "the hook must not be re-run while routing is down"
        );
    }

    #[test]
    fn dns_probe_targets_are_every_dns_server_pinned_through_the_tunnel() {
        let v4 = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        let resource = Ipv4Addr::new(203, 0, 113, 10);
        let cloudflare_v6: Vec<String> = vec!["2606:4700:4700::1111".to_string()];

        let full = RouteManager::new(gate_params(true, v4.clone(), vec![]), "/nonexistent/script".to_string());
        assert_eq!(
            full.dns_probe_targets(),
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
            "a first responder that never answers must not hide a working second one"
        );

        let split = RouteManager::new(gate_params(false, v4.clone(), vec![resource]), "/nonexistent/script".to_string());
        assert_eq!(
            split.dns_probe_targets(),
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
            "split + resources pins DNS"
        );

        let bare = RouteManager::new(gate_params(false, v4.clone(), vec![]), "/nonexistent/script".to_string());
        assert!(bare.dns_probe_targets().is_empty(), "bare split mode never advertises DNS");

        let no_dns = RouteManager::new(gate_params(true, vec![], vec![]), "/nonexistent/script".to_string());
        assert!(no_dns.dns_probe_targets().is_empty(), "nothing configured, nothing to probe");

        let mixed = RouteManager::new(
            gate_params(true, vec!["2606:4700:4700::1111".to_string(), "9.9.9.9".to_string()], vec![]),
            "/nonexistent/script".to_string(),
        );
        assert_eq!(
            mixed.dns_probe_targets(),
            vec![Ipv4Addr::new(9, 9, 9, 9)],
            "every IPv4 responder is probed even behind an IPv6 one"
        );

        let only_v6 = RouteManager::new(gate_params(true, cloudflare_v6, vec![]), "/nonexistent/script".to_string());
        assert!(
            only_v6.dns_probe_targets().is_empty(),
            "the TUN is IPv4-only, so v6 servers are never pinned"
        );

        let hostname = RouteManager::new(
            gate_params(true, vec!["dns.example".to_string()], vec![]),
            "/nonexistent/script".to_string(),
        );
        assert!(
            hostname.dns_probe_targets().is_empty(),
            "a non-literal server name cannot be probed"
        );
    }

    // BUG: specs/bugs/BUG-tunnel-dns-single-probe-target.md
    #[test]
    fn dns_gate_advertises_only_the_responders_that_answered() {
        let servers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        let mut mgr = RouteManager::new(gate_params(true, servers, vec![]), "/nonexistent/script".to_string());
        let dead = Ipv4Addr::new(1, 1, 1, 1);
        let live = Ipv4Addr::new(8, 8, 8, 8);

        assert!(
            mgr.observe_dns_health(&[live]),
            "dropping a dead responder from the advertisement is a change"
        );
        let env = mgr.render_env();
        assert!(
            env.contains("PRRR_DNS_GATE=on"),
            "one live responder keeps DNS in the tunnel: {env}"
        );
        assert!(
            env.contains("PRRR_DNS_ADVERTISE_SERVERS=\"8.8.8.8\""),
            "the unresponsive server must not be handed to the system resolver: {env}"
        );
        assert!(
            env.contains("PRRR_DNS_SERVERS=\"1.1.1.1 8.8.8.8\""),
            "both servers stay pinned so the probe keeps measuring the tunnel: {env}"
        );

        assert!(!mgr.observe_dns_health(&[live]), "the same live set is not a change");

        assert!(mgr.observe_dns_health(&[]), "losing the last responder closes the gate");
        assert!(mgr.render_env().contains("PRRR_DNS_GATE=off"));

        assert!(mgr.observe_dns_health(&[dead, live]), "a recovered responder is a change");
        assert!(
            mgr.render_env().contains("PRRR_DNS_ADVERTISE_SERVERS=\"1.1.1.1 8.8.8.8\""),
            "an advertised server returns as soon as it answers again"
        );
    }

    #[test]
    fn resource_domains_are_only_the_names_the_tunnel_carries() {
        // BUG: specs/bugs/BUG-split-mode-dns-catchall-hijacks-host-resolver.md
        let params = RouteParams {
            resources: vec![
                "chatgpt.com".to_string(),
                " t.me ".to_string(),
                "203.0.113.9".to_string(),
                "198.51.100.0/24".to_string(),
                String::new(),
            ],
            ..gate_params(false, vec!["1.1.1.1".to_string()], vec![])
        };
        let mgr = RouteManager::new(params, "/nonexistent/script".to_string());

        assert_eq!(
            mgr.dns_resource_domains(),
            vec!["chatgpt.com".to_string(), "t.me".to_string()],
            "literal addresses and blanks are not names to route by"
        );
    }

    #[test]
    fn env_publishes_resource_domains_so_the_hook_can_scope_dns() {
        // BUG: specs/bugs/BUG-split-mode-dns-catchall-hijacks-host-resolver.md
        let params = RouteParams {
            resources: vec!["chatgpt.com".to_string(), "t.me".to_string()],
            ..gate_params(false, vec!["1.1.1.1".to_string()], vec![])
        };
        let mgr = RouteManager::new(params, "/nonexistent/script".to_string());

        assert!(
            mgr.render_env().contains("PRRR_RESOURCE_DOMAINS=\"chatgpt.com t.me\""),
            "the hook cannot scope what the binary does not publish: {}",
            mgr.render_env()
        );
    }

    #[test]
    fn dns_gate_never_withdraws_an_ipv6_server_it_cannot_probe() {
        let servers = vec!["2606:4700:4700::1111".to_string(), "1.1.1.1".to_string(), "8.8.8.8".to_string()];
        let mut mgr = RouteManager::new(gate_params(true, servers, vec![]), "/nonexistent/script".to_string());

        mgr.observe_dns_health(&[Ipv4Addr::new(8, 8, 8, 8)]);
        let env = mgr.render_env();
        assert!(
            env.contains("PRRR_DNS_ADVERTISE_SERVERS=\"2606:4700:4700::1111 8.8.8.8\""),
            "only probed IPv4 servers can be judged dead: {env}"
        );
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
            resources: vec![],
            resource_ips: vec![],
            fwmark: DEFAULT_FWMARK,
        };
        let mut mgr = RouteManager::new(params, "/nonexistent/script".to_string());
        // Calling down() when not up should be a no-op
        mgr.down();
        mgr.down();
    }
}
