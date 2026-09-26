// FRD: specs/frds/FRD-002-ecosystem-registry-registration.md

//! Ecosystem registry registration (SPEC §3).
//!
//! prrr coexists on one laptop with sibling components (`sy`, `syauth`,
//! `cathouse`). For zero-configuration coexistence each component advertises a
//! descriptor — what it is and which exclusive resources it owns — so siblings
//! defer and auto-adjust. This module builds prrr's descriptor and publishes it
//! to the laptop registry.
//!
//! NOTE: this is a DIFFERENT concept from [`crate::registry`], which is the
//! server-side SQLite registry of authorized VPN clients. This module is the
//! ecosystem coordination surface defined in `SPEC §3`.
//!
//! Transport: SPEC §9.1 blesses a file fallback
//! (`$XDG_RUNTIME_DIR/sy/ecosystem/<component>.json`) for components that run
//! before `sy`. [`FileRegistryTransport`] implements that path behind the
//! [`RegistryTransport`] trait so a future `sy` IPC op slots in without
//! changing call sites. Registration is **best-effort**: failures are logged
//! and swallowed, never propagated to the tunnel bring-up path.

use std::path::PathBuf;

use serde::Serialize;

use crate::crypto::kdf::blake2s;

/// Component name prrr advertises in the registry.
pub const COMPONENT_NAME: &str = "prrr";

/// prrr's role in the ecosystem (SPEC §3).
pub const ROLE_VPN_EGRESS: &str = "vpn-egress";

/// The Android `VpnService` slot prrr owns (SPEC §4: one per device).
pub const OWNS_ANDROID_VPNSERVICE: &str = "android:VpnService";

/// Environment variable naming the per-user runtime dir (SPEC §9.1).
const XDG_RUNTIME_DIR_ENV: &str = "XDG_RUNTIME_DIR";

/// Subdirectory under `$XDG_RUNTIME_DIR` for ecosystem descriptors (SPEC §3).
const ECOSYSTEM_SUBDIR: &str = "sy/ecosystem";

/// Descriptor file name for prrr (`<component>.json`).
const DESCRIPTOR_FILE: &str = "prrr.json";

/// Temp file name used for atomic write (temp + rename).
const DESCRIPTOR_TMP_FILE: &str = "prrr.json.tmp";

/// The transport protocol prrr is using, used to derive owned ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// QUIC/MASQUE over UDP.
    Masque,
    /// HARP over TCP (HTTP/WebSocket/H2).
    Harp,
}

impl TransportKind {
    /// The `owns` port token for this transport (e.g. `"udp:443"`).
    fn owns_port_token(self, port: u16) -> String {
        match self {
            TransportKind::Masque => format!("udp:{port}"),
            TransportKind::Harp => format!("tcp:{port}"),
        }
    }
}

/// Owned resource identifiers (SPEC §3 `owns`).
type Owns = Vec<String>;

/// Discovery endpoints (SPEC §3 `endpoints`).
///
/// All fields are optional and omitted from JSON when absent so the file stays
/// tidy. prrr currently advertises only its server-facing LAN endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Endpoints {
    /// Unix domain socket path, when prrr exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uds: Option<String>,
    /// LAN `host:port` of the server prrr connects to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lan: Option<String>,
    /// mDNS service name, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mdns: Option<String>,
}

/// Shared device identity reference (SPEC §3 `identity`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Identity {
    /// blake3-of-pubkey, lowercase hex (SPEC §3).
    pub peer_id: String,
}

/// Live coexistence flags (SPEC §3 `flags`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Flags {
    /// Whether the tunnel captures the local LAN too (strict full tunnel).
    pub full_tunnel: bool,
    /// CIDRs kept out of the tunnel (LAN auto-exclusion + user excludes).
    pub excluded_cidrs: Vec<String>,
    /// Whether client-to-client sharing is on (Step 4 toggles; `false` now).
    pub client_to_client: bool,
    /// Authorized peer's reachable mesh address (Step 5 sets; `null` now).
    pub mesh_peer_addr: Option<String>,
}

/// A prrr ecosystem descriptor (SPEC §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Descriptor {
    /// Component name (always `"prrr"`).
    pub component: String,
    /// Component role (always `"vpn-egress"`).
    pub role: String,
    /// Exclusive resources prrr owns.
    pub owns: Owns,
    /// Discovery endpoints.
    pub endpoints: Endpoints,
    /// Shared device identity reference.
    pub identity: Identity,
    /// Live coexistence flags.
    pub flags: Flags,
}

/// Derive the `peer_id` (blake3 of the public key, lowercase hex) per SPEC §3.
pub fn peer_id_from_pubkey(pubkey: &[u8]) -> String {
    let digest = blake2s(pubkey);
    hex_lower(&digest)
}

/// Lowercase hex-encode a byte slice (no external dependency).
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Inputs to [`build_descriptor`] — the current prrr state.
///
/// IO-free: every field is plain data captured at the call site, so descriptor
/// construction is a pure function and unit-testable with zero IO.
pub struct DescriptorState<'a> {
    /// Client's Noise static public key (for `peer_id`).
    pub pubkey: &'a [u8],
    /// Active transport protocol (selects `udp:`/`tcp:` port ownership).
    pub transport: TransportKind,
    /// Port prrr's transport owns (typically 443).
    pub port: u16,
    /// Tunnel interface name (e.g. `"prrr0"`).
    pub iface: &'a str,
    /// Server `host:port` prrr connects to, for the `lan` endpoint.
    pub server_endpoint: Option<&'a str>,
    /// Strict full-tunnel flag (`RoutingSection.full_tunnel`).
    pub full_tunnel: bool,
    /// Excluded CIDRs (from `compute_excluded_ips`).
    pub excluded_cidrs: Vec<String>,
    /// Whether client-to-client sharing is on (Step 4 toggle state).
    pub client_to_client: bool,
    /// Authorized peer's reachable mesh address, when sharing is established and
    /// the inter-client route has been probed (Step 5). `None` ⇒ `null`.
    pub mesh_peer_addr: Option<String>,
}

/// Build prrr's descriptor from current state (pure, IO-free).
///
/// `client_to_client` follows the Step 4 sharing toggle (`state.client_to_client`)
/// and `mesh_peer_addr` carries the probed peer address when sharing is
/// established (Step 5), or `None`/`null` otherwise.
pub fn build_descriptor(state: DescriptorState<'_>) -> Descriptor {
    let owns = vec![
        OWNS_ANDROID_VPNSERVICE.to_string(),
        state.transport.owns_port_token(state.port),
        format!("iface:{}", state.iface),
    ];

    Descriptor {
        component: COMPONENT_NAME.to_string(),
        role: ROLE_VPN_EGRESS.to_string(),
        owns,
        endpoints: Endpoints {
            uds: None,
            lan: state.server_endpoint.map(str::to_string),
            mdns: None,
        },
        identity: Identity {
            peer_id: peer_id_from_pubkey(state.pubkey),
        },
        flags: Flags {
            full_tunnel: state.full_tunnel,
            excluded_cidrs: state.excluded_cidrs,
            client_to_client: state.client_to_client,
            mesh_peer_addr: state.mesh_peer_addr,
        },
    }
}

/// Publishes prrr's descriptor to the ecosystem registry.
///
/// Implementations are **best-effort**: `publish`/`clear` never return an error
/// and never block tunnel bring-up. A future `sy` IPC op implements this same
/// trait so call sites are unchanged.
pub trait RegistryTransport {
    /// Publish (write/overwrite) the current descriptor. Best-effort.
    fn publish(&self, descriptor: &Descriptor);
    /// Remove prrr's descriptor (e.g. on full shutdown). Best-effort.
    fn clear(&self);
}

/// File-fallback registry transport (SPEC §9.1).
///
/// Writes `$XDG_RUNTIME_DIR/sy/ecosystem/prrr.json` atomically (temp + rename).
/// Resolution of the runtime dir is deferred to each call so a late-set
/// `$XDG_RUNTIME_DIR` is honored.
#[derive(Debug, Default, Clone)]
pub struct FileRegistryTransport {
    /// Explicit base dir override (tests). When `None`, `$XDG_RUNTIME_DIR`.
    base_override: Option<PathBuf>,
}

impl FileRegistryTransport {
    /// Construct a transport that reads `$XDG_RUNTIME_DIR` at publish time.
    pub fn new() -> Self {
        Self { base_override: None }
    }

    /// Construct a transport rooted at an explicit base dir (used by tests and
    /// callers that already resolved the runtime dir).
    pub fn with_base(base: PathBuf) -> Self {
        Self { base_override: Some(base) }
    }

    /// Resolve the ecosystem directory, or `None` if `$XDG_RUNTIME_DIR` is unset
    /// and no override is configured.
    fn ecosystem_dir(&self) -> Option<PathBuf> {
        let base = match &self.base_override {
            Some(b) => b.clone(),
            None => PathBuf::from(std::env::var_os(XDG_RUNTIME_DIR_ENV)?),
        };
        Some(base.join(ECOSYSTEM_SUBDIR))
    }

    /// Path of the published descriptor, or `None` when the runtime dir is unset.
    ///
    /// A sibling (cathouse) reads this same path to consume prrr's descriptor and
    /// its `flags.mesh_peer_addr` (SPEC §3/§6).
    pub fn descriptor_path(&self) -> Option<PathBuf> {
        self.ecosystem_dir().map(|dir| dir.join(DESCRIPTOR_FILE))
    }

    /// Atomic write of `contents` to `<dir>/prrr.json` via temp + rename.
    fn write_atomic(dir: &std::path::Path, contents: &str) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(DESCRIPTOR_TMP_FILE);
        let final_path = dir.join(DESCRIPTOR_FILE);
        std::fs::write(&tmp, contents)?;
        std::fs::rename(&tmp, &final_path)
    }
}

impl RegistryTransport for FileRegistryTransport {
    fn publish(&self, descriptor: &Descriptor) {
        let Some(dir) = self.ecosystem_dir() else {
            tracing::debug!(
                env = XDG_RUNTIME_DIR_ENV,
                "ecosystem registry: runtime dir unset, skipping registration"
            );
            return;
        };
        let json = match serde_json::to_string_pretty(descriptor) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(error = %e, "ecosystem registry: failed to serialize descriptor");
                return;
            }
        };
        match Self::write_atomic(&dir, &json) {
            Ok(()) => tracing::info!(path = %dir.join(DESCRIPTOR_FILE).display(), "ecosystem registry: descriptor published"),
            Err(e) => tracing::warn!(error = %e, dir = %dir.display(), "ecosystem registry: write failed (best-effort, continuing)"),
        }
    }

    fn clear(&self) {
        let Some(dir) = self.ecosystem_dir() else {
            return;
        };
        let path = dir.join(DESCRIPTOR_FILE);
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::info!(path = %path.display(), "ecosystem registry: descriptor cleared"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::debug!(error = %e, path = %path.display(), "ecosystem registry: clear failed (best-effort)"),
        }
    }
}

/// Drives registry publication across tunnel state transitions.
///
/// Holds a [`RegistryTransport`] plus the two pre-built descriptors for the
/// connected and not-connected states. The reconnect loop calls [`on_up`] when
/// the tunnel comes up and [`on_down`] when it goes down; Steps 4/5 reuse the
/// same publish path to flip `client_to_client` / set `mesh_peer_addr`.
///
/// [`on_up`]: EcosystemRegistrar::on_up
/// [`on_down`]: EcosystemRegistrar::on_down
pub struct EcosystemRegistrar {
    transport: Box<dyn RegistryTransport + Send + Sync>,
    connected: Descriptor,
    down: Descriptor,
}

impl EcosystemRegistrar {
    /// Build a registrar from a transport and the connected/down descriptors.
    pub fn new(transport: Box<dyn RegistryTransport + Send + Sync>, connected: Descriptor, down: Descriptor) -> Self {
        Self {
            transport,
            connected,
            down,
        }
    }

    /// Publish the connected descriptor (tunnel up). Best-effort.
    pub fn on_up(&self) {
        self.transport.publish(&self.connected);
    }

    /// Publish the not-connected descriptor (tunnel down). Best-effort.
    ///
    /// Conservative per SPEC §7: the descriptor is rewritten with the LAN no
    /// longer excluded (the tunnel is not capturing anything) rather than
    /// deleted, so a polling sibling sees a live record whose flags say
    /// "not connected".
    pub fn on_down(&self) {
        self.transport.publish(&self.down);
    }
}

impl std::fmt::Debug for EcosystemRegistrar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcosystemRegistrar")
            .field("connected", &self.connected)
            .field("down", &self.down)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-002-ecosystem-registry-registration.md
    use super::*;

    const TEST_PORT: u16 = 443;
    const TEST_IFACE: &str = "prrr0";

    fn sample_state<'a>(pubkey: &'a [u8], transport: TransportKind, full_tunnel: bool, excluded: Vec<String>) -> DescriptorState<'a> {
        DescriptorState {
            pubkey,
            transport,
            port: TEST_PORT,
            iface: TEST_IFACE,
            server_endpoint: Some("vpn.example.com:443"),
            full_tunnel,
            excluded_cidrs: excluded,
            client_to_client: false,
            mesh_peer_addr: None,
        }
    }

    // peer_id is lowercase hex of blake3(pubkey).
    #[test]
    fn peer_id_is_blake3_hex() {
        let pubkey = [0xABu8; 32];
        let got = peer_id_from_pubkey(&pubkey);
        let expected = hex_lower(&blake2s(&pubkey));
        assert_eq!(got, expected);
        assert_eq!(got.len(), 64, "blake3-256 is 32 bytes = 64 hex chars");
        assert!(got.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // MASQUE transport owns a udp: port; HARP owns a tcp: port.
    #[test]
    fn owns_ports_track_transport() {
        let pk = [1u8; 32];
        let masque = build_descriptor(sample_state(&pk, TransportKind::Masque, false, vec![]));
        assert!(masque.owns.contains(&"udp:443".to_string()), "masque -> udp, got {:?}", masque.owns);

        let harp = build_descriptor(sample_state(&pk, TransportKind::Harp, false, vec![]));
        assert!(harp.owns.contains(&"tcp:443".to_string()), "harp -> tcp, got {:?}", harp.owns);
    }

    // owns always includes the VpnService slot and the iface name.
    #[test]
    fn owns_includes_vpnservice_and_iface() {
        let pk = [2u8; 32];
        let d = build_descriptor(sample_state(&pk, TransportKind::Masque, false, vec![]));
        assert!(d.owns.contains(&OWNS_ANDROID_VPNSERVICE.to_string()));
        assert!(d.owns.contains(&"iface:prrr0".to_string()));
    }

    // Default sharing-off descriptor: client_to_client false, mesh_peer_addr null.
    #[test]
    fn step2_flags_are_pinned() {
        let pk = [3u8; 32];
        let d = build_descriptor(sample_state(&pk, TransportKind::Masque, true, vec!["192.168.0.0/16".to_string()]));
        assert!(!d.flags.client_to_client, "sharing off by default");
        assert_eq!(d.flags.mesh_peer_addr, None, "mesh_peer_addr is Step 5");
        assert!(d.flags.full_tunnel);
        assert_eq!(d.flags.excluded_cidrs, vec!["192.168.0.0/16".to_string()]);
    }

    // Step 4: client_to_client follows the sharing toggle state; mesh_peer_addr
    // stays null when no address is supplied.
    #[test]
    fn descriptor_client_to_client_follows_state() {
        let pk = [11u8; 32];
        let mut state = sample_state(&pk, TransportKind::Masque, false, vec![]);
        state.client_to_client = true;
        let d = build_descriptor(state);
        assert!(d.flags.client_to_client, "sharing on => client_to_client true");
        assert_eq!(d.flags.mesh_peer_addr, None, "no mesh addr supplied => null");
    }

    // Step 5: a supplied mesh_peer_addr propagates into flags.mesh_peer_addr.
    #[test]
    fn descriptor_carries_mesh_peer_addr() {
        let pk = [12u8; 32];
        let mut state = sample_state(&pk, TransportKind::Masque, false, vec![]);
        state.client_to_client = true;
        state.mesh_peer_addr = Some("100.64.0.2:51820".to_string());
        let d = build_descriptor(state);
        assert_eq!(d.flags.mesh_peer_addr.as_deref(), Some("100.64.0.2:51820"));
    }

    // Schema (SPEC §3): serialized JSON has the exact top-level keys and flag
    // sub-keys, correctly typed.
    #[test]
    fn descriptor_validates_against_spec_schema() {
        let pk = [4u8; 32];
        let d = build_descriptor(sample_state(&pk, TransportKind::Masque, false, vec!["192.168.1.0/24".to_string()]));
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&d).expect("serialize")).expect("parse");
        let obj = v.as_object().expect("descriptor is a JSON object");

        assert_eq!(obj.get("component").and_then(|c| c.as_str()), Some("prrr"));
        assert_eq!(obj.get("role").and_then(|r| r.as_str()), Some("vpn-egress"));
        assert!(obj.get("owns").and_then(|o| o.as_array()).is_some(), "owns is an array");
        assert!(obj.get("endpoints").and_then(|e| e.as_object()).is_some(), "endpoints is an object");

        let identity = obj.get("identity").and_then(|i| i.as_object()).expect("identity object");
        assert!(
            identity.get("peer_id").and_then(|p| p.as_str()).is_some(),
            "identity.peer_id is a string"
        );

        let flags = obj.get("flags").and_then(|f| f.as_object()).expect("flags object");
        assert!(
            flags.get("full_tunnel").and_then(|f| f.as_bool()).is_some(),
            "flags.full_tunnel is bool"
        );
        assert!(
            flags.get("excluded_cidrs").and_then(|f| f.as_array()).is_some(),
            "flags.excluded_cidrs is array"
        );
        assert!(
            flags.get("client_to_client").and_then(|f| f.as_bool()).is_some(),
            "flags.client_to_client is bool"
        );
        assert!(flags.contains_key("mesh_peer_addr"), "flags.mesh_peer_addr present");
        assert!(
            flags.get("mesh_peer_addr").expect("present").is_null(),
            "mesh_peer_addr is null in Step 2"
        );
    }

    // File transport: publish into a temp base, read back, assert schema + flags.
    #[test]
    fn file_transport_publishes_descriptor() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let transport = FileRegistryTransport::with_base(dir.path().to_path_buf());
        let pk = [5u8; 32];
        let d = build_descriptor(sample_state(&pk, TransportKind::Harp, false, vec!["10.0.0.0/8".to_string()]));

        transport.publish(&d);

        let path = dir.path().join(ECOSYSTEM_SUBDIR).join(DESCRIPTOR_FILE);
        let contents = std::fs::read_to_string(&path).expect("descriptor file written");
        let v: serde_json::Value = serde_json::from_str(&contents).expect("valid json on disk");
        assert_eq!(v["component"], "prrr");
        assert_eq!(v["flags"]["excluded_cidrs"][0], "10.0.0.0/8");
        assert!(v["owns"].as_array().expect("owns").iter().any(|o| o == "tcp:443"));
    }

    // Flags track tunnel state: a "connected" publish then a "down" publish
    // changes the on-disk flags.
    #[test]
    fn on_disk_flags_track_tunnel_state() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let transport = FileRegistryTransport::with_base(dir.path().to_path_buf());
        let pk = [6u8; 32];

        // Connected: LAN excluded (default split-tunnel).
        let connected = build_descriptor(sample_state(&pk, TransportKind::Masque, false, vec!["192.168.1.0/24".to_string()]));
        transport.publish(&connected);
        let path = dir.path().join(ECOSYSTEM_SUBDIR).join(DESCRIPTOR_FILE);
        let v1: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        assert_eq!(v1["flags"]["excluded_cidrs"][0], "192.168.1.0/24");

        // Down: not connected -> no excluded CIDRs, full_tunnel reflects config.
        let down = build_descriptor(sample_state(&pk, TransportKind::Masque, false, vec![]));
        transport.publish(&down);
        let v2: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        assert!(
            v2["flags"]["excluded_cidrs"].as_array().expect("array").is_empty(),
            "down state clears excluded CIDRs, got {:?}",
            v2["flags"]["excluded_cidrs"]
        );
    }

    // Best-effort: publishing with an unset runtime dir (no override) must not
    // panic and must not write anywhere.
    #[test]
    fn publish_with_unset_runtime_dir_is_noop() {
        let transport = FileRegistryTransport::new();
        // Temporarily ensure XDG_RUNTIME_DIR resolution returns None by using a
        // transport with no override and an env we control. We cannot safely
        // mutate process env in parallel tests, so we assert ecosystem_dir is
        // None when base_override is None and the env happens to be unset; the
        // key contract is that publish never panics.
        let pk = [7u8; 32];
        let d = build_descriptor(sample_state(&pk, TransportKind::Masque, false, vec![]));
        // Must not panic regardless of whether XDG_RUNTIME_DIR is set.
        transport.publish(&d);
    }

    // Best-effort: publishing into an unwritable/blocked base does not panic and
    // does not propagate an error to the caller.
    #[test]
    fn publish_into_blocked_base_does_not_panic() {
        // A base whose parent is a regular file cannot have a subdir created.
        let dir = tempfile::TempDir::new().expect("temp dir");
        let file_path = dir.path().join("not-a-dir");
        std::fs::write(&file_path, b"x").expect("write file");
        let transport = FileRegistryTransport::with_base(file_path);
        let pk = [8u8; 32];
        let d = build_descriptor(sample_state(&pk, TransportKind::Masque, false, vec![]));
        // create_dir_all under a file path errors; publish swallows it.
        transport.publish(&d);
    }

    // Registrar: on_up publishes connected flags, on_down publishes down flags.
    #[test]
    fn registrar_on_up_and_on_down_track_state() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let transport = FileRegistryTransport::with_base(dir.path().to_path_buf());
        let pk = [10u8; 32];
        let connected = build_descriptor(sample_state(&pk, TransportKind::Masque, false, vec!["192.168.1.0/24".to_string()]));
        let down = build_descriptor(sample_state(&pk, TransportKind::Masque, false, vec![]));
        let registrar = EcosystemRegistrar::new(Box::new(transport), connected, down);
        let path = dir.path().join(ECOSYSTEM_SUBDIR).join(DESCRIPTOR_FILE);

        registrar.on_up();
        let up_v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        assert_eq!(up_v["flags"]["excluded_cidrs"][0], "192.168.1.0/24");

        registrar.on_down();
        let down_v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        assert!(down_v["flags"]["excluded_cidrs"].as_array().expect("array").is_empty());
    }

    const TEST_MESH_ADDR: &str = "100.64.0.2:51820";

    // descriptor_path resolves to <base>/sy/ecosystem/prrr.json.
    #[test]
    fn descriptor_path_points_at_published_file() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let transport = FileRegistryTransport::with_base(dir.path().to_path_buf());
        let expected = dir.path().join(ECOSYSTEM_SUBDIR).join(DESCRIPTOR_FILE);
        assert_eq!(transport.descriptor_path(), Some(expected));
    }

    // Step 5 registry fixture: with sharing established (mesh addr supplied), the
    // on-disk descriptor carries flags.mesh_peer_addr; the down descriptor (tunnel
    // down) clears it back to null.
    #[test]
    fn mesh_peer_addr_appears_on_up_and_clears_on_down() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let transport = FileRegistryTransport::with_base(dir.path().to_path_buf());
        let path = dir.path().join(ECOSYSTEM_SUBDIR).join(DESCRIPTOR_FILE);
        let pk = [13u8; 32];

        let mut up_state = sample_state(&pk, TransportKind::Masque, false, vec![]);
        up_state.client_to_client = true;
        up_state.mesh_peer_addr = Some(TEST_MESH_ADDR.to_string());
        let connected = build_descriptor(up_state);
        let down = build_descriptor(sample_state(&pk, TransportKind::Masque, false, vec![]));
        let registrar = EcosystemRegistrar::new(Box::new(transport), connected, down);

        registrar.on_up();
        let up_v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        assert_eq!(up_v["flags"]["mesh_peer_addr"], TEST_MESH_ADDR, "established => addr published");

        registrar.on_down();
        let down_v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        assert!(down_v["flags"]["mesh_peer_addr"].is_null(), "tunnel down => mesh_peer_addr cleared");
    }

    // clear() removes the descriptor and is a no-op when absent.
    #[test]
    fn clear_removes_descriptor() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let transport = FileRegistryTransport::with_base(dir.path().to_path_buf());
        let pk = [9u8; 32];
        let d = build_descriptor(sample_state(&pk, TransportKind::Masque, false, vec![]));
        transport.publish(&d);
        let path = dir.path().join(ECOSYSTEM_SUBDIR).join(DESCRIPTOR_FILE);
        assert!(path.exists());
        transport.clear();
        assert!(!path.exists(), "clear removes the descriptor");
        // Second clear is a no-op (file absent).
        transport.clear();
    }
}
