// FRD: specs/frds/FRD-004-client-sharing-toggle-and-remote-enable.md

//! Client-to-client sharing toggle and authorized remote enable (Step 4).
//!
//! prrr is the enforcement point for inter-client routing. This module owns:
//!
//! - [`SharingState`] — the explicit, persisted client switch (`enabled` plus
//!   the peer mesh address, which stays `None` until Step 5);
//! - pure transitions [`SharingState::enabled`]/[`enable`]/[`disable`];
//! - [`SharingStore`] — a fail-closed JSON store so `prrr sharing status`
//!   reflects on-disk reality and the daemon honors it;
//! - the authorized remote-enable path: a [`RemoteEnableRequest`] relayed from
//!   `sy`/cathouse (SPEC §9.4) is honored **only** when the server-side pair
//!   authorization exists (`ClientRegistry::is_pair_allowed`) **and** the
//!   per-use biometric signature verifies ([`authorize_remote_enable`]).
//!
//! ## Signature primitive (see FRD-004 "Assumption")
//!
//! prrr ships no Ed25519 key material of its own (SPEC §7 attributes Ed25519 to
//! syauth). prrr's job is only to *verify* the per-use biometric signature
//! carried in the relayed request. We reuse prrr's existing keyed-MAC scheme
//! (the same `blake3::Hasher::new_keyed` + constant-time `subtle` compare used
//! for prekey signatures in [`crate::messaging::keys`]) behind the
//! [`BiometricVerifier`] trait, so a future asymmetric verifier is a drop-in.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Domain separator binding a biometric signature to a remote-enable request.
const REMOTE_ENABLE_SIG_DOMAIN: &[u8] = b"prrr-sharing-remote-enable-v1";

/// Byte length of a keyed-MAC biometric signature (BLAKE3 output).
pub const BIOMETRIC_SIG_LEN: usize = 32;

/// Default file name for the persisted sharing state.
pub const SHARING_STATE_FILENAME: &str = "sharing.json";

/// Explicit client-to-client sharing state (FRD-004).
///
/// `peer_mesh_addr` is always `None` in Step 4 — it is set in Step 5 once the
/// inter-client route is confirmed up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharingState {
    /// Whether the client has opted into inter-client routing.
    pub enabled: bool,
    /// Authorized peer's reachable mesh address (Step 5 sets this; `None` now).
    pub peer_mesh_addr: Option<String>,
}

impl SharingState {
    /// Whether inter-client routing is currently accepted by this client.
    ///
    /// This is the "off = no route" gate (FRD-004 routing AC): when sharing is
    /// disabled the client never accepts an inter-client route.
    pub fn route_accepted(&self) -> bool {
        self.enabled
    }

    /// Return a copy with sharing enabled (pure transition).
    pub fn enable(&self) -> Self {
        Self {
            enabled: true,
            peer_mesh_addr: self.peer_mesh_addr.clone(),
        }
    }

    /// Return a copy with sharing established to a probed peer mesh address.
    ///
    /// Step 5 transition: sharing is enabled AND the authorized peer's reachable
    /// `host:port` is recorded so it can be propagated to `flags.mesh_peer_addr`.
    /// Call only after the address has been probed (see [`resolve_mesh_addr`]).
    pub fn establish(&self, peer_mesh_addr: &str) -> Self {
        Self {
            enabled: true,
            peer_mesh_addr: Some(peer_mesh_addr.to_string()),
        }
    }

    /// Return a copy with sharing disabled (pure transition).
    ///
    /// Disabling also drops any learned peer mesh address: the route is gone, so
    /// the address is no longer reachable (and must not linger for Step 5).
    pub fn disable(&self) -> Self {
        Self {
            enabled: false,
            peer_mesh_addr: None,
        }
    }
}

/// Why an authorized remote-enable request was refused (fail-closed, SPEC §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RefusedReason {
    /// No server-side sharing-pair authorization exists for the two clients.
    #[error("refused: no server-side pair authorization")]
    NoPairAuthorization,
    /// The request carried no per-use biometric signature.
    #[error("refused: missing biometric signature")]
    MissingSignature,
    /// The per-use biometric signature did not verify against the trusted key.
    #[error("refused: bad biometric signature")]
    BadSignature,
}

/// A remote enable request relayed from `sy`/cathouse (SPEC §9.4).
///
/// The relay names the two clients to pair (`requester`/`peer`) and a per-use
/// `nonce` (binds the signature so a captured request cannot be replayed
/// against a different context). `signature` is the per-use biometric signature
/// over the canonical request bytes; `None` means the request is unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEnableRequest {
    /// The local client being asked to enable sharing.
    pub requester: Uuid,
    /// The authorized peer the local client should route to.
    pub peer: Uuid,
    /// Per-use nonce bound into the signed bytes (anti-replay).
    pub nonce: u64,
    /// Per-use biometric signature, or `None` when the request is unsigned.
    pub signature: Option<[u8; BIOMETRIC_SIG_LEN]>,
}

impl RemoteEnableRequest {
    /// Canonical, domain-separated bytes the biometric signature covers.
    ///
    /// Binds requester, peer, and the per-use nonce so a signature is valid for
    /// exactly one (requester, peer, nonce) context.
    fn signed_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(REMOTE_ENABLE_SIG_DOMAIN.len() + 16 + 16 + 8);
        bytes.extend_from_slice(REMOTE_ENABLE_SIG_DOMAIN);
        bytes.extend_from_slice(self.requester.as_bytes());
        bytes.extend_from_slice(self.peer.as_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        bytes
    }
}

/// Verifies the per-use biometric signature carried in a remote-enable request.
///
/// Abstracted so the keyed-MAC stand-in (Step 4) can be swapped for an
/// asymmetric Ed25519 verifier when syauth's key material is threaded through,
/// with no change at the [`authorize_remote_enable`] call site.
pub trait BiometricVerifier {
    /// Return `true` iff `signature` is a valid per-use biometric signature over
    /// `message` (constant-time).
    fn verify(&self, message: &[u8], signature: &[u8; BIOMETRIC_SIG_LEN]) -> bool;
}

/// Keyed-MAC biometric verifier reusing prrr's existing signature primitive.
///
/// `mac = BLAKE3-keyed(key = trusted_key, data = message)`, compared in constant
/// time. The trusted key is the per-use biometric signing key shared by the
/// relay authority out-of-band (SPEC §7: prrr verifies on its own channel).
pub struct KeyedMacVerifier {
    /// The trusted per-use biometric signing key.
    trusted_key: [u8; BIOMETRIC_SIG_LEN],
}

impl KeyedMacVerifier {
    /// Construct a verifier bound to the trusted per-use biometric key.
    pub fn new(trusted_key: [u8; BIOMETRIC_SIG_LEN]) -> Self {
        Self { trusted_key }
    }

    /// Produce the keyed MAC for `message` under the trusted key.
    ///
    /// Exposed so a relay/test holding the same key can produce a valid
    /// signature; production relays sign with syauth's biometric path.
    pub fn sign(&self, message: &[u8]) -> [u8; BIOMETRIC_SIG_LEN] {
        let mut hasher = blake3::Hasher::new_keyed(&self.trusted_key);
        hasher.update(message);
        *hasher.finalize().as_bytes()
    }
}

impl BiometricVerifier for KeyedMacVerifier {
    fn verify(&self, message: &[u8], signature: &[u8; BIOMETRIC_SIG_LEN]) -> bool {
        let expected = self.sign(message);
        expected.ct_eq(signature).into()
    }
}

/// The enforcement heart (FRD-004): authorize a relayed remote-enable request.
///
/// Returns `Ok(())` **only** when both hold, re-checked live:
/// 1. the server-side pair authorization exists (`is_pair_allowed`), AND
/// 2. the per-use biometric signature verifies against the trusted key.
///
/// Any miss returns a typed [`RefusedReason`] and makes **no** state change.
/// prrr never enables sharing on an unauthorized or unsigned request.
pub fn authorize_remote_enable<V: BiometricVerifier>(
    req: &RemoteEnableRequest,
    registry: &crate::registry::ClientRegistry,
    verifier: &V,
) -> Result<(), RefusedReason> {
    if !registry.is_pair_allowed(req.requester, req.peer) {
        return Err(RefusedReason::NoPairAuthorization);
    }
    let signature = req.signature.as_ref().ok_or(RefusedReason::MissingSignature)?;
    if !verifier.verify(&req.signed_bytes(), signature) {
        return Err(RefusedReason::BadSignature);
    }
    Ok(())
}

/// Apply a remote-enable request to the current state.
///
/// On authorization success, returns the enabled state; on refusal, returns the
/// typed reason and the state is left for the caller to keep unchanged.
pub fn apply_remote_request<V: BiometricVerifier>(
    state: &SharingState,
    req: &RemoteEnableRequest,
    registry: &crate::registry::ClientRegistry,
    verifier: &V,
) -> Result<SharingState, RefusedReason> {
    authorize_remote_enable(req, registry, verifier)?;
    Ok(state.enable())
}

/// Fail-closed JSON store for [`SharingState`].
///
/// Reads return the default (disabled) state on any error, so a corrupt or
/// missing file never enables sharing. Writes are atomic (temp + rename).
#[derive(Debug, Clone)]
pub struct SharingStore {
    path: PathBuf,
}

impl SharingStore {
    /// Construct a store backed by `path` (typically `<config>/sharing.json`).
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load the persisted state, or the default (disabled) state on any error.
    ///
    /// Fail-closed (SPEC §7): a missing or malformed file yields `disabled`.
    pub fn load(&self) -> SharingState {
        let Ok(contents) = std::fs::read_to_string(&self.path) else {
            return SharingState::default();
        };
        serde_json::from_str(&contents).unwrap_or_default()
    }

    /// Persist `state` atomically (temp file + rename).
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if the directory cannot be created or
    /// the file cannot be written/renamed.
    pub fn store(&self, state: &SharingState) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &self.path)
    }
}

/// Probes whether an authorized peer's mesh address is actually reachable.
///
/// Injected so the publish decision ([`resolve_mesh_addr`]) is unit-testable
/// without real network IO. The default [`TcpMeshProbe`] does a bounded TCP
/// connect; a future asymmetric/handshake probe is a drop-in (Step 5 risk:
/// probe before publish so a non-routable address is never advertised).
pub trait MeshProbe {
    /// Return `true` iff `addr` (`host:port`) is reachable right now.
    fn probe(&self, addr: &str) -> bool;
}

/// Decide the address to publish into `flags.mesh_peer_addr` (pure, fail-closed).
///
/// Returns `Some(addr)` **only** when sharing is established (`enabled`), a
/// candidate peer mesh address is known, AND the probe confirms it reachable.
/// Any miss returns `None`, so a non-routable or speculative address is never
/// advertised (SPEC §7: publish only routable facts).
pub fn resolve_mesh_addr<P: MeshProbe>(enabled: bool, candidate: Option<&str>, probe: &P) -> Option<String> {
    let addr = candidate?;
    if enabled && probe.probe(addr) {
        Some(addr.to_string())
    } else {
        None
    }
}

/// Default [`MeshProbe`]: a bounded TCP connect to the candidate address.
///
/// Reachability is "a TCP connection completes within the timeout". The timeout
/// keeps a black-hole address from blocking the publish path (Stressor 9). For
/// addresses that resolve to several sockets, success on any one counts.
#[derive(Debug, Clone)]
pub struct TcpMeshProbe {
    /// Per-connect timeout bound.
    timeout: std::time::Duration,
}

/// Default connect-timeout for [`TcpMeshProbe`], in milliseconds.
pub const MESH_PROBE_TIMEOUT_MS: u64 = 750;

impl Default for TcpMeshProbe {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_millis(MESH_PROBE_TIMEOUT_MS),
        }
    }
}

impl MeshProbe for TcpMeshProbe {
    fn probe(&self, addr: &str) -> bool {
        use std::net::ToSocketAddrs;
        let Ok(socket_addrs) = addr.to_socket_addrs() else {
            tracing::debug!(addr, "mesh probe: address did not resolve, not publishing");
            return false;
        };
        for socket_addr in socket_addrs {
            if std::net::TcpStream::connect_timeout(&socket_addr, self.timeout).is_ok() {
                return true;
            }
        }
        tracing::debug!(addr, "mesh probe: not reachable, not publishing non-routable mesh addr");
        false
    }
}

/// Decide whether the local client reaches `peer` over the inter-client mesh.
///
/// This is the client-side reach gate that mirrors Step 3's server-side
/// `may_forward`: the route is reachable **only** when the local client has
/// opted in (`state.enabled`, the "off = no route" gate) **and** the server-side
/// pair authorization exists (`registry.is_pair_allowed`). Either condition
/// missing ⇒ no route (fail-closed).
pub fn mesh_reachable(state: &SharingState, registry: &crate::registry::ClientRegistry, local: Uuid, peer: Uuid) -> bool {
    state.route_accepted() && registry.is_pair_allowed(local, peer)
}

/// Resolve the default sharing-state path under the client config directory.
///
/// Mirrors the client config location (`$HOME/.config/prrr/sharing.json`).
pub fn default_state_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".config/prrr").join(SHARING_STATE_FILENAME)
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-004-client-sharing-toggle-and-remote-enable.md
    use super::*;
    use crate::registry::ClientRegistry;

    const TEST_SUBNET: &str = "10.66.66.0/24";
    const TEST_KEY: [u8; BIOMETRIC_SIG_LEN] = [0x42; BIOMETRIC_SIG_LEN];
    const TEST_NONCE: u64 = 7;

    fn paired_registry() -> (ClientRegistry, Uuid, Uuid) {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("subnet");
        let a = reg.add("alice", [0x01; 32], None).expect("add a").id;
        let b = reg.add("bob", [0x02; 32], None).expect("add b").id;
        reg.allow_pair(a, b).expect("allow");
        (reg, a, b)
    }

    fn signed_request(a: Uuid, b: Uuid, verifier: &KeyedMacVerifier) -> RemoteEnableRequest {
        let mut req = RemoteEnableRequest {
            requester: a,
            peer: b,
            nonce: TEST_NONCE,
            signature: None,
        };
        let sig = verifier.sign(&req.signed_bytes());
        req.signature = Some(sig);
        req
    }

    const TEST_MESH_ADDR: &str = "100.64.0.2:51820";

    struct FixedProbe(bool);
    impl MeshProbe for FixedProbe {
        fn probe(&self, _addr: &str) -> bool {
            self.0
        }
    }

    #[test]
    fn resolve_mesh_addr_publishes_when_enabled_and_probe_ok() {
        let got = resolve_mesh_addr(true, Some(TEST_MESH_ADDR), &FixedProbe(true));
        assert_eq!(got, Some(TEST_MESH_ADDR.to_string()), "enabled + probe ok => publish");
    }

    #[test]
    fn resolve_mesh_addr_none_when_probe_fails() {
        let got = resolve_mesh_addr(true, Some(TEST_MESH_ADDR), &FixedProbe(false));
        assert_eq!(got, None, "probe fail => no publish (fail-closed)");
    }

    #[test]
    fn resolve_mesh_addr_none_when_sharing_off() {
        let got = resolve_mesh_addr(false, Some(TEST_MESH_ADDR), &FixedProbe(true));
        assert_eq!(got, None, "sharing off => no publish even if reachable");
    }

    #[test]
    fn enable_sets_enabled() {
        let s = SharingState::default().enable();
        assert!(s.enabled);
        assert_eq!(s.peer_mesh_addr, None, "mesh_peer_addr is Step 5");
        assert!(s.route_accepted());
    }

    #[test]
    fn tcp_probe_reachable_open_port_ok() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        assert!(TcpMeshProbe::default().probe(&addr), "open port is reachable");
    }

    #[test]
    fn tcp_probe_unreachable_or_malformed_fails() {
        // Closed port: bind then drop the listener so the port is free again is
        // racy; instead use a malformed address which can never resolve.
        assert!(!TcpMeshProbe::default().probe("not-a-valid-host:port"), "malformed => unreachable");
    }

    #[test]
    fn establish_sets_enabled_and_addr() {
        let s = SharingState::default().establish(TEST_MESH_ADDR);
        assert!(s.enabled);
        assert_eq!(s.peer_mesh_addr.as_deref(), Some(TEST_MESH_ADDR));
    }

    #[test]
    fn disable_clears_established_addr() {
        let s = SharingState::default().establish(TEST_MESH_ADDR).disable();
        assert_eq!(s.peer_mesh_addr, None, "disable clears the mesh address");
    }

    #[test]
    fn disable_clears_enabled() {
        let s = SharingState::default().enable().disable();
        assert!(!s.enabled);
        assert!(!s.route_accepted(), "off = no route");
    }

    #[test]
    fn store_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SharingStore::new(dir.path().join(SHARING_STATE_FILENAME));
        let state = SharingState::default().enable();
        store.store(&state).expect("store");
        assert_eq!(store.load(), state);
    }

    #[test]
    fn corrupt_store_loads_disabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(SHARING_STATE_FILENAME);
        std::fs::write(&path, "{not valid json").expect("write");
        let store = SharingStore::new(path);
        assert_eq!(store.load(), SharingState::default(), "fail-closed: disabled");
        assert!(!store.load().enabled);
    }

    #[test]
    fn missing_store_loads_disabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SharingStore::new(dir.path().join("absent.json"));
        assert!(!store.load().enabled, "missing file => disabled");
    }

    #[test]
    fn authorize_valid_signed_and_paired_ok() {
        let (reg, a, b) = paired_registry();
        let verifier = KeyedMacVerifier::new(TEST_KEY);
        let req = signed_request(a, b, &verifier);
        assert_eq!(authorize_remote_enable(&req, &reg, &verifier), Ok(()));
    }

    #[test]
    fn authorize_no_pair_refused() {
        let mut reg = ClientRegistry::new(TEST_SUBNET).expect("subnet");
        let a = reg.add("alice", [0x01; 32], None).expect("a").id;
        let b = reg.add("bob", [0x02; 32], None).expect("b").id;
        // No allow_pair: server-side authorization absent.
        let verifier = KeyedMacVerifier::new(TEST_KEY);
        let req = signed_request(a, b, &verifier);
        assert_eq!(
            authorize_remote_enable(&req, &reg, &verifier),
            Err(RefusedReason::NoPairAuthorization)
        );
    }

    #[test]
    fn authorize_unsigned_refused() {
        let (reg, a, b) = paired_registry();
        let verifier = KeyedMacVerifier::new(TEST_KEY);
        let req = RemoteEnableRequest {
            requester: a,
            peer: b,
            nonce: TEST_NONCE,
            signature: None,
        };
        assert_eq!(authorize_remote_enable(&req, &reg, &verifier), Err(RefusedReason::MissingSignature));
    }

    #[test]
    fn authorize_bad_signature_refused() {
        let (reg, a, b) = paired_registry();
        let verifier = KeyedMacVerifier::new(TEST_KEY);
        let mut req = signed_request(a, b, &verifier);
        // Flip a byte: signature no longer verifies.
        if let Some(sig) = req.signature.as_mut() {
            sig[0] ^= 0xFF;
        }
        assert_eq!(authorize_remote_enable(&req, &reg, &verifier), Err(RefusedReason::BadSignature));
    }

    #[test]
    fn authorize_wrong_key_refused() {
        let (reg, a, b) = paired_registry();
        let signer = KeyedMacVerifier::new(TEST_KEY);
        let req = signed_request(a, b, &signer);
        // Verifier holds a different trusted key than the signer.
        let verifier = KeyedMacVerifier::new([0x99; BIOMETRIC_SIG_LEN]);
        assert_eq!(authorize_remote_enable(&req, &reg, &verifier), Err(RefusedReason::BadSignature));
    }

    #[test]
    fn apply_remote_request_enables_on_ok() {
        let (reg, a, b) = paired_registry();
        let verifier = KeyedMacVerifier::new(TEST_KEY);
        let req = signed_request(a, b, &verifier);
        let next = apply_remote_request(&SharingState::default(), &req, &reg, &verifier).expect("ok");
        assert!(next.enabled);
    }

    #[test]
    fn apply_remote_request_unauthorized_unchanged() {
        let (reg, a, b) = paired_registry();
        let verifier = KeyedMacVerifier::new(TEST_KEY);
        let unsigned = RemoteEnableRequest {
            requester: a,
            peer: b,
            nonce: TEST_NONCE,
            signature: None,
        };
        let before = SharingState::default();
        let result = apply_remote_request(&before, &unsigned, &reg, &verifier);
        assert!(result.is_err(), "refused");
        // State the caller keeps is unchanged (still disabled).
        assert!(!before.enabled);
    }

    #[test]
    fn route_accepted_only_when_enabled() {
        assert!(!SharingState::default().route_accepted(), "off => no route");
        assert!(SharingState::default().enable().route_accepted(), "on => route");
    }

    // FRD-004 routing AC: with sharing on AND server-authorized, the two clients
    // reach each other over the mesh; with sharing off, they cannot.
    #[test]
    fn mesh_reachable_requires_enabled_and_paired() {
        let (reg, a, b) = paired_registry();
        let off = SharingState::default();
        let on = off.enable();

        assert!(mesh_reachable(&on, &reg, a, b), "on + paired => reachable");
        assert!(!mesh_reachable(&off, &reg, a, b), "off = no route even when paired");

        // On but the server-side pair is not authorized => not reachable.
        let mut unpaired = ClientRegistry::new(TEST_SUBNET).expect("subnet");
        let x = unpaired.add("x", [0x05; 32], None).expect("x").id;
        let y = unpaired.add("y", [0x06; 32], None).expect("y").id;
        assert!(!mesh_reachable(&on, &unpaired, x, y), "on but no pair => no route");
    }
}
