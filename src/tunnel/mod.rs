// FRD: specs/frds/FRD-008.md

//! IP tunneling: TUN device abstraction and packet pipeline.
//!
//! Provides a [`TunDevice`] trait for reading/writing IP packets,
//! a [`MockTun`] for testing without root privileges, and a
//! [`TunnelPipeline`] that wires TUN ↔ EncryptedChannel ↔ MASQUE
//! for bidirectional IP packet tunneling.

pub mod mock_tun;
pub mod pipeline;
pub mod tun_device;

pub use mock_tun::{CapturingMockTunFactory, MockTun, MockTunFactory, MockTunHandle};
pub use pipeline::TunnelPipeline;
#[cfg(feature = "system-tun")]
pub use tun_device::{SystemTun, SystemTunFactory};
pub use tun_device::{TunConfig, TunDevice};

/// Factory trait for creating per-client TUN devices.
///
/// Used by the multi-client server to create a fresh TUN device for
/// each accepted client connection. The [`TunConfig`] provides the
/// client's assigned IP address and device parameters.
pub trait TunFactory: Send + Sync + 'static {
    /// The TUN device type this factory produces.
    type Tun: TunDevice;
    /// Handle type returned alongside each TUN device (for test injection/capture).
    type Handle: Send + 'static;

    /// Create a new TUN device and its associated handle.
    ///
    /// The `config` provides the per-client TUN parameters (IP address,
    /// device name, MTU). Mock factories may ignore the config.
    ///
    /// # Errors
    ///
    /// Returns [`TunnelError`] if the TUN device cannot be created.
    fn create_tun(&self, config: &TunConfig) -> Result<(Self::Tun, Self::Handle), TunnelError>;
}

/// Errors produced by tunnel operations.
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    /// TUN device I/O error.
    #[error("TUN device error: {0}")]
    TunIo(#[from] std::io::Error),

    /// Transport layer error (encryption/decryption, MASQUE framing).
    #[error("transport error: {0}")]
    Transport(#[from] crate::transport::TransportError),

    /// Packet exceeds the configured MTU.
    #[error("packet too large: {size} bytes exceeds MTU {mtu}")]
    PacketTooLarge {
        /// Actual packet size.
        size: usize,
        /// Configured MTU.
        mtu: u16,
    },

    /// Pipeline was cancelled via cancellation token.
    #[error("pipeline cancelled")]
    Cancelled,
}
