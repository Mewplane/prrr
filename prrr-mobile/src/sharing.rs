// FRD: specs/frds/FRD-004-client-sharing-toggle-and-remote-enable.md

//! Mobile sharing-toggle seam (Step 4).
//!
//! The vendor-neutral Rust core ([`prrr::sharing`]) holds the real
//! client-to-client sharing state and all enforcement logic. Android's
//! signature-`protectionLevel` `ContentProvider` (SPEC §3/§9.3) is a *thin*
//! wrapper that calls these UniFFI-exported functions; the provider holds no
//! truth of its own, so co-signed ecosystem apps observe one consistent state.
//!
//! Each function takes the state-file path the app owns (its private files dir),
//! so the seam is pure with respect to that path and unit-testable with a temp
//! file — exactly like [`prrr::sharing::SharingStore`].

use std::path::PathBuf;

use prrr::sharing::{SharingState, SharingStore};

/// Sharing state surfaced to the Android toggle (mirrors [`SharingState`]).
///
/// `peer_mesh_addr` is `None` in Step 4; Step 5 populates it once the
/// inter-client route is confirmed up.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SharingStateDto {
    /// Whether the client has opted into inter-client routing.
    pub enabled: bool,
    /// Authorized peer's reachable mesh address (`None` until Step 5).
    pub peer_mesh_addr: Option<String>,
}

impl From<SharingState> for SharingStateDto {
    fn from(s: SharingState) -> Self {
        Self {
            enabled: s.enabled,
            peer_mesh_addr: s.peer_mesh_addr,
        }
    }
}

/// Read the current sharing state from the app-owned state file (fail-closed).
///
/// A missing or corrupt file yields the disabled default, so the Android toggle
/// never shows "on" without a real on-disk opt-in.
#[uniffi::export]
pub fn sharing_get_state(state_path: String) -> SharingStateDto {
    SharingStore::new(PathBuf::from(state_path)).load().into()
}

/// Flip the sharing toggle and persist it; returns the resulting state.
///
/// `enabled == true` opts into inter-client routing; `false` opts out (and drops
/// any learned peer mesh address). Persisted atomically by the core store.
///
/// # Errors
///
/// Returns the I/O error string if the state file cannot be written.
#[uniffi::export]
pub fn sharing_set_enabled(state_path: String, enabled: bool) -> Result<SharingStateDto, crate::MobileError> {
    let store = SharingStore::new(PathBuf::from(state_path));
    let current = store.load();
    let next = if enabled { current.enable() } else { current.disable() };
    store.store(&next).map_err(|e| crate::MobileError::TunnelFailed {
        reason: format!("sharing state write failed: {e}"),
    })?;
    Ok(next.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE_FILE: &str = "sharing.json";

    /// Build a unique temp dir for the test (no tempfile dev-dep needed).
    fn unique_dir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("prrr-mobile-sharing-{nanos}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    // FRD-004: the UniFFI seam toggle drives the persisted Rust state, and a
    // subsequent get reflects it (Android observes one source of truth).
    #[test]
    fn mobile_seam_toggle_drives_state() {
        let dir = unique_dir();
        let path = dir.join(STATE_FILE).to_string_lossy().into_owned();

        // Default (no file) => disabled, fail-closed.
        assert!(!sharing_get_state(path.clone()).enabled);

        let on = sharing_set_enabled(path.clone(), true).expect("enable");
        assert!(on.enabled);
        assert_eq!(on.peer_mesh_addr, None, "mesh addr is Step 5");
        assert!(sharing_get_state(path.clone()).enabled, "get reflects set");

        let off = sharing_set_enabled(path.clone(), false).expect("disable");
        assert!(!off.enabled);
        assert!(!sharing_get_state(path).enabled, "off persists");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
