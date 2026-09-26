// FRD: specs/frds/FRD-001-local-lan-auto-exclusion.md

//! Mobile route-set computation: local-LAN auto-exclusion (split-tunnel courtesy).
//!
//! The vendor-neutral Rust core ([`prrr::routing`]) is the single source of
//! truth for which prefixes to keep out of the tunnel. Android's
//! `PrrrVpnService` calls [`lan_excluded_cidrs`] and feeds each returned CIDR to
//! `VpnService.Builder.excludeRoute()`, so the phone and the laptop apply the
//! same rule with no platform-specific routing logic.

use prrr::routing::{compute_excluded_ips, InterfaceEnumerator, SystemInterfaceEnumerator};

/// The tunnel's own logical subnet, which must never be auto-excluded.
const TUN_SUBNET: &str = "10.66.66.0/24";

/// Compute the RFC1918 local-LAN CIDRs the Android `VpnService` should exclude.
///
/// Enumerates the device's active interfaces and returns their RFC1918 network
/// prefixes (the LAN), excluding the tunnel's own subnet. When `full_tunnel` is
/// `true`, returns an empty list so the tunnel captures LAN traffic too (strict
/// full-tunnel escape hatch).
#[uniffi::export]
pub fn lan_excluded_cidrs(full_tunnel: bool) -> Vec<String> {
    let interfaces = SystemInterfaceEnumerator.enumerate();
    compute_excluded_ips(&[], &interfaces, &[TUN_SUBNET.to_string()], full_tunnel)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strict full-tunnel returns no auto-excluded LAN CIDRs (escape hatch).
    /// Mutant killed: if `full_tunnel` is ignored, LAN prefixes would leak in.
    #[test]
    fn strict_full_tunnel_excludes_nothing() {
        assert!(lan_excluded_cidrs(true).is_empty());
    }

    /// Default mode never auto-excludes the tunnel's own subnet (would break the
    /// tunnel). Mutant killed: if the skip list is dropped.
    #[test]
    fn default_never_excludes_tunnel_subnet() {
        assert!(!lan_excluded_cidrs(false).contains(&TUN_SUBNET.to_string()));
    }
}
