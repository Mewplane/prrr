// FRD: specs/frds/FRD-005.md

/// Encrypted bidirectional channel with nonce management and replay protection.
pub mod encrypted_channel;
/// HTTP/2 stream adapters for DatagramSender / DatagramReceiver.
pub mod h2_adapter;
/// HARP frame codec for HTTPS API Relay Protocol.
pub mod harp;
/// MASQUE CONNECT-UDP framing over QUIC DATAGRAMs (RFC 9297/9298).
pub mod masque;
/// QUIC client and server transport (quinn-based).
pub mod quic;
/// Shared TLS certificate verification.
pub(crate) mod tls;
/// Pluggable transport abstraction layer (traits + shared types).
pub mod traits;

pub use traits::{
    BoxedDatagramReceiver, BoxedDatagramSender, ClientConnectParams, ClientTransport, ServerTransport, SharedServerState,
    TransportConnection,
};

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

    /// HARP frame is shorter than the minimum header size.
    #[error("HARP frame too short: expected at least {expected} bytes, got {actual}")]
    HarpFrameTooShort {
        /// Minimum valid frame length (header size).
        expected: usize,
        /// Actual frame length received.
        actual: usize,
    },

    /// HARP frame has an unsupported protocol version.
    #[error("HARP unsupported version: {0}")]
    HarpUnsupportedVersion(u8),

    /// HARP frame payload is truncated (fewer bytes than declared length).
    #[error("HARP frame truncated: header declares {header_len} payload bytes, only {available} available")]
    HarpFrameTruncated {
        /// Payload length declared in the header.
        header_len: usize,
        /// Bytes actually available after the header.
        available: usize,
    },

    /// HARP frame payload exceeds the maximum allowed size.
    #[error("HARP payload too large: {0} bytes exceeds maximum 65535")]
    HarpPayloadTooLarge(usize),

    /// HARP frame has an unrecognized frame type value.
    #[error("HARP unknown frame type: {0:#x}")]
    HarpUnknownFrameType(u8),

    /// HARP session channel was closed (session removed from store).
    #[error("HARP channel closed")]
    HarpChannelClosed,

    /// HARP CLOSE frame received (peer requested session teardown).
    #[error("HARP session closed by peer")]
    HarpSessionClosed,

    /// HTTP/2 stream-level error (send or receive).
    #[error("H2 stream error: {0}")]
    H2Stream(String),
}
