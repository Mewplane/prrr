// FRD: specs/frds/FRD-M006-mobile-documentation.md
// FRD: specs/frds/FRD-M002-uniffi-interface.md

/// Errors that can occur during mobile library operations.
///
/// All error variants include descriptive messages to help with debugging
/// and provide user-facing error information.
///
/// # Examples
///
/// ```no_run
/// use prrr_mobile::{parse_qr_config, MobileError};
///
/// match parse_qr_config("invalid-qr".to_string()) {
///     Ok(config) => println!("Parsed: {}", config.client_name),
///     Err(MobileError::InvalidConfig { reason }) => {
///         println!("Invalid QR code: {}", reason);
///     }
///     Err(e) => println!("Error: {}", e),
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum MobileError {
    /// Configuration validation or parsing failed.
    ///
    /// This error occurs when:
    /// - QR code format is incorrect (not `prrr://import?config=...`)
    /// - Base64 decoding fails
    /// - TOML parsing fails
    /// - Required fields are missing
    /// - Key lengths are invalid (must be 32 bytes for X25519, 1184 for ML-KEM-768)
    /// - IP address is not in CIDR format
    /// - MTU is out of range (1280-1500)
    #[error("invalid config: {reason}")]
    InvalidConfig {
        /// Detailed reason for the configuration error
        reason: String,
    },

    /// VPN connection attempt failed.
    ///
    /// This indicates a network-level failure during connection establishment,
    /// such as DNS resolution failure, unreachable server, or timeout.
    #[error("connection failed: {reason}")]
    ConnectionFailed {
        /// Detailed reason for the connection failure
        reason: String,
    },

    /// Cryptographic handshake failed.
    ///
    /// This indicates the hybrid Noise IK + ML-KEM-768 handshake did not
    /// complete successfully. Possible causes include key mismatch or
    /// protocol version incompatibility.
    #[error("handshake failed: {reason}")]
    HandshakeFailed {
        /// Detailed reason for the handshake failure
        reason: String,
    },

    /// Network operation failed.
    ///
    /// General network errors such as socket errors, DNS failures,
    /// or packet transmission failures.
    #[error("network error: {reason}")]
    NetworkError {
        /// Detailed reason for the network error
        reason: String,
    },

    /// Operation requires an active connection but none exists.
    ///
    /// Thrown when attempting operations like getting statistics
    /// while in disconnected state.
    #[error("not connected")]
    NotConnected,
}
