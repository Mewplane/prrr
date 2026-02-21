// FRD: specs/frds/FRD-003.md

/// Hybrid Noise IK + ML-KEM-768 handshake.
pub mod hybrid;
/// Noise IK handshake pattern implementation.
pub mod noise_ik;

/// Errors produced by handshake operations.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// The handshake message failed authentication or decryption.
    #[error("handshake message authentication failed")]
    MessageAuthFailed,

    /// The handshake is not yet complete; transport mode unavailable.
    #[error("handshake not finished")]
    NotFinished,

    /// The transport-mode message failed decryption or authentication.
    #[error("transport decryption failed")]
    TransportDecryptFailed,

    /// An internal error in the Noise state machine.
    #[error("noise state machine error: {0}")]
    NoiseError(String),

    /// ML-KEM operation failed during hybrid handshake.
    #[error("KEM operation failed: {0}")]
    KemFailed(String),
}
