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

pub use config::{parse_qr_config, validate_config, VpnConfig};
pub use connection::{ConnectionStats, ConnectionStatus, VpnConnection};
pub use error::MobileError;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

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
