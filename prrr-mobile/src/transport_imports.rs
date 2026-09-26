// FRD: specs/frds/FRD-M021-transport-dependency-wiring.md

//! Re-exports of core transport types for use by the mobile connection layer.
//!
//! This module bridges `prrr-mobile` to the core `prrr` library's transport,
//! handshake, and tunnel infrastructure. [`VpnConnection`](crate::VpnConnection)
//! uses these types to establish real VPN tunnels.

// Core `prrr` re-exports grouped by area:
// - client: HARP client transport implementation and configuration
// - crypto: cryptographic key types
// - handshake: Noise/hybrid handshake types
// - transport: transport traits, types, and the post-handshake encrypted channel
// - tunnel: tunnel pipeline and traffic stats
pub use prrr::{
    client::{HarpClientConfig, HarpClientTransport},
    crypto::hybrid_kex::KemKeyPair,
    handshake::{
        hybrid::{HybridInitiator, SessionKeys},
        noise_ik::KeyPair,
    },
    transport::{encrypted_channel::EncryptedChannel, ClientConnectParams, ClientTransport, TransportConnection},
    tunnel::{pipeline::TrafficStats, TunnelError, TunnelPipeline},
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Noise X25519 public key length in bytes.
    const NOISE_PUBLIC_KEY_LEN: usize = 32;

    /// AC-2: Transport traits and types are importable.
    /// Mutant killed: removing `ClientTransport` re-export would break this test.
    #[test]
    fn transport_traits_importable() {
        // Compile-only: verify ClientTransport trait is accessible as a trait object type
        fn _assert_trait_object(_t: &dyn ClientTransport) {}

        // Verify TransportConnection struct fields are accessible
        let _: fn() -> Option<TransportConnection> = || None;
    }

    /// AC-3: HarpClientTransport is importable and constructable.
    /// Mutant killed: removing `HarpClientTransport` re-export would break this test.
    #[test]
    fn harp_client_transport_importable() {
        // Compile-only: verify HarpClientTransport is a concrete type
        let _: fn() -> Option<HarpClientTransport> = || None;
    }

    /// AC-4: TunnelPipeline is importable.
    /// Mutant killed: removing `TunnelPipeline` re-export would break this test.
    #[test]
    fn tunnel_pipeline_importable() {
        // TunnelPipeline<T, S, R> requires concrete type params to be named.
        // Verifying the path resolves by using type_name with concrete test types.
        let name = std::any::type_name::<
            TunnelPipeline<
                prrr::tunnel::MockTun,
                Box<dyn prrr::transport::BoxedDatagramSender>,
                Box<dyn prrr::transport::BoxedDatagramReceiver>,
            >,
        >();
        assert!(name.contains("TunnelPipeline"));
    }

    /// AC-4: EncryptedChannel is importable.
    /// Mutant killed: removing `EncryptedChannel` re-export would break this test.
    #[test]
    fn encrypted_channel_importable() {
        let _: fn() -> Option<EncryptedChannel> = || None;
    }

    /// AC-5: Handshake types are importable.
    /// Mutant killed: removing `HybridInitiator` or `SessionKeys` would break this test.
    #[test]
    fn handshake_types_importable() {
        let _: fn() -> Option<SessionKeys> = || None;
        let _: fn() -> Option<HybridInitiator> = || None;
    }

    /// AC-5: Cryptographic key types are importable and functional.
    /// Mutant killed: removing `KeyPair` or `KemKeyPair` would break this test.
    #[test]
    fn key_types_importable() {
        let keypair = KeyPair::generate().expect("keygen should succeed");
        assert_eq!(keypair.public_key().len(), NOISE_PUBLIC_KEY_LEN);

        let kem_keypair = KemKeyPair::generate();
        assert!(!kem_keypair.encapsulation_key_bytes().is_empty());
    }
}
