// FRD: specs/frds/FRD-005.md

/// Encrypted bidirectional channel with nonce management and replay protection.
pub mod encrypted_channel;
/// MASQUE CONNECT-UDP framing over QUIC DATAGRAMs (RFC 9297/9298).
pub mod masque;
/// QUIC client and server transport (quinn-based).
pub mod quic;

/// Errors produced by transport-layer operations.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// AEAD decryption or authentication failed (tampered or wrong key).
    #[error("transport decryption failed")]
    DecryptionFailed,

    /// A previously-seen nonce was replayed (duplicate or out-of-window packet).
    #[error("replay detected: nonce {0} already seen or outside window")]
    ReplayDetected(u64),

    /// Wire bytes are shorter than the minimum valid packet.
    #[error("packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort {
        /// Minimum valid packet length.
        expected: usize,
        /// Actual packet length received.
        actual: usize,
    },

    /// Key derivation failed during rekey.
    #[error("rekey failed: {0}")]
    RekeyFailed(String),

    /// QUIC connection failed.
    #[error("QUIC connection error: {0}")]
    QuicConnection(String),

    /// QUIC stream write failed.
    #[error("QUIC write error: {0}")]
    QuicWrite(String),

    /// QUIC stream read failed.
    #[error("QUIC read error: {0}")]
    QuicRead(String),

    /// TLS or certificate configuration error.
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    /// The server endpoint could not bind to the requested address.
    #[error("bind failed: {0}")]
    BindFailed(String),

    /// MASQUE CONNECT-UDP handshake failed.
    #[error("MASQUE handshake error: {0}")]
    MasqueHandshake(String),

    /// MASQUE datagram framing error.
    #[error("MASQUE datagram error: {0}")]
    MasqueDatagram(String),

    /// QUIC variable-length integer decoding failed.
    #[error("varint decode error: {0}")]
    VarintDecode(String),
}
