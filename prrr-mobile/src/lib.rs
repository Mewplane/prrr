// FRD: specs/frds/FRD-M002-uniffi-interface.md

//! prrr mobile library
//!
//! This library provides the core prrr VPN protocol functionality for mobile platforms (iOS and Android).
//! It is designed to be consumed via FFI (Foreign Function Interface) using UniFFI bindings.

// Allow unsafe in scaffolding only - UniFFI generates FFI code which is inherently unsafe
// Allow empty_line_after_doc_comments - UniFFI 0.28 generated code has this pattern
#![allow(clippy::empty_line_after_doc_comments)]
#![warn(missing_docs)]

mod config;
mod connection;
mod error;
/// Local-LAN auto-exclusion route-set computation for the Android VpnService.
pub mod routing;
/// Client-to-client sharing toggle seam for the Android ContentProvider (Step 4).
pub mod sharing;
/// Re-exports of core transport types for mobile connection layer.
pub mod transport_imports;
/// Android TUN device adapter for `TunnelPipeline`.
pub mod tun_adapter;

pub use config::{parse_qr_config, validate_config, VpnConfig};
pub use connection::{ConnectionStats, ConnectionStatus, VpnConnection};
pub use error::MobileError;
pub use routing::lan_excluded_cidrs;
pub use sharing::{sharing_get_state, sharing_set_enabled, SharingStateDto};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize tracing (Android logcat when available, stderr otherwise).
pub(crate) fn init_logging() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        #[cfg(feature = "android-logging")]
        {
            use tracing_subscriber::{layer::SubscriberExt, EnvFilter};
            let filter = EnvFilter::new("prrr=debug,prrr_mobile=debug,info");
            let android_layer = tracing_android::layer("prrr-mobile").expect("android tracing layer");
            let subscriber = tracing_subscriber::registry().with(filter).with(android_layer);
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        #[cfg(not(feature = "android-logging"))]
        {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("prrr=debug,prrr_mobile=debug,info")
                .try_init();
        }
    });
}

// UniFFI scaffolding
uniffi::include_scaffolding!("mobile");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_exists() {
        assert!(!VERSION.is_empty());
        assert_eq!(VERSION, "0.1.0");
    }
}
