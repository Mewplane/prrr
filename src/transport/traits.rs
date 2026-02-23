// FRD: specs/frds/FRD-20260223-transport-trait-abstraction.md

//! Pluggable transport abstraction layer.
//!
//! Defines the [`ClientTransport`] and [`ServerTransport`] traits that
//! any transport (MASQUE, HARP, etc.) must implement to integrate with
//! the prrr VPN core. Also defines [`SharedServerState`] for shared
//! server infrastructure and [`TransportConnection`] as the unified
//! return type from client-side transport connections.

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::crypto::hybrid_kex::KemKeyPair;
use crate::handshake::hybrid::SessionKeys;
use crate::handshake::noise_ik::KeyPair;
use crate::registry::ClientRegistry;
use crate::transport::TransportError;

/// Noise X25519 public key length in bytes.
const NOISE_PUBLIC_KEY_LEN: usize = 32;

/// Parameters shared across all transports for client-side connection.
///
/// Borrows cryptographic material from the caller to avoid cloning
/// key bytes. The [`CancellationToken`] is cheaply cloneable and owned.
pub struct ClientConnectParams<'a> {
    /// Client's Noise X25519 static keypair.
    pub noise_keypair: &'a KeyPair,
    /// Server's Noise X25519 public key (32 bytes).
    pub server_noise_pub: &'a [u8; NOISE_PUBLIC_KEY_LEN],
    /// Server's ML-KEM-768 encapsulation key (DER-encoded).
    pub server_kem_pub: &'a [u8],
    /// Cancellation token for cooperative shutdown.
    pub cancel: CancellationToken,
}

/// Dyn-compatible trait for sending datagrams through a transport.
///
/// This mirrors [`DatagramSender`] from `tunnel::pipeline` but is
/// dyn-compatible, allowing type-erased transport connections.
///
/// [`DatagramSender`]: crate::tunnel::pipeline::DatagramSender
pub trait BoxedDatagramSender: Send + Sync {
    /// Send a datagram payload through the transport.
    fn send_datagram(&self, payload: &[u8]) -> Result<(), TransportError>;
}

/// Dyn-compatible trait for receiving datagrams from a transport.
///
/// Unlike [`DatagramReceiver`] (which uses `impl Future`), this trait
/// returns a pinned boxed future for dyn-compatibility.
///
/// [`DatagramReceiver`]: crate::tunnel::pipeline::DatagramReceiver
pub trait BoxedDatagramReceiver: Send + Sync {
    /// Receive a datagram payload from the transport.
    fn recv_datagram(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>>;
}

/// Blanket impl: any [`DatagramSender`] is also a [`BoxedDatagramSender`].
///
/// [`DatagramSender`]: crate::tunnel::pipeline::DatagramSender
impl<T: crate::tunnel::pipeline::DatagramSender> BoxedDatagramSender for T {
    fn send_datagram(&self, payload: &[u8]) -> Result<(), TransportError> {
        crate::tunnel::pipeline::DatagramSender::send_datagram(self, payload)
    }
}

/// Blanket impl: any [`DatagramReceiver`] is also a [`BoxedDatagramReceiver`].
///
/// [`DatagramReceiver`]: crate::tunnel::pipeline::DatagramReceiver
impl<T: crate::tunnel::pipeline::DatagramReceiver> BoxedDatagramReceiver for T {
    fn recv_datagram(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>> {
        Box::pin(crate::tunnel::pipeline::DatagramReceiver::recv_datagram(self))
    }
}

/// [`DatagramSender`] adapter for `Box<dyn BoxedDatagramSender>`.
///
/// Allows a boxed transport sender to be used with [`TunnelPipeline`].
///
/// [`DatagramSender`]: crate::tunnel::pipeline::DatagramSender
/// [`TunnelPipeline`]: crate::tunnel::TunnelPipeline
impl crate::tunnel::pipeline::DatagramSender for Box<dyn BoxedDatagramSender> {
    fn send_datagram(&self, payload: &[u8]) -> Result<(), TransportError> {
        (**self).send_datagram(payload)
    }
}

/// [`DatagramReceiver`] adapter for `Box<dyn BoxedDatagramReceiver>`.
///
/// Allows a boxed transport receiver to be used with [`TunnelPipeline`].
///
/// [`DatagramReceiver`]: crate::tunnel::pipeline::DatagramReceiver
/// [`TunnelPipeline`]: crate::tunnel::TunnelPipeline
impl crate::tunnel::pipeline::DatagramReceiver for Box<dyn BoxedDatagramReceiver> {
    async fn recv_datagram(&self) -> Result<Vec<u8>, TransportError> {
        BoxedDatagramReceiver::recv_datagram(&**self).await
    }
}

/// Result of a successful transport connection (client or server side).
///
/// Contains the datagram sender/receiver pair for the [`TunnelPipeline`]
/// and the [`SessionKeys`] derived from the hybrid handshake.
///
/// [`TunnelPipeline`]: crate::tunnel::TunnelPipeline
pub struct TransportConnection {
    /// Sender for outbound datagrams (TUN → network).
    pub sender: Box<dyn BoxedDatagramSender>,
    /// Receiver for inbound datagrams (network → TUN).
    pub receiver: Box<dyn BoxedDatagramReceiver>,
    /// Session keys derived from the hybrid Noise IK + ML-KEM handshake.
    pub session_keys: SessionKeys,
}

/// Client-side transport: connect to a server and return a transport connection.
///
/// Each implementation encapsulates a specific transport protocol
/// (e.g., QUIC/MASQUE, HTTPS/HARP) and performs the cryptographic
/// handshake to derive [`SessionKeys`].
///
/// # Dyn-compatibility
///
/// `connect` returns a pinned boxed future so that `Box<dyn ClientTransport>`
/// works without the `async_trait` macro.
pub trait ClientTransport: Send + Sync {
    /// Human-readable transport name (e.g., `"masque"`, `"harp"`).
    fn name(&self) -> &str;

    /// Connect to the server and perform the cryptographic handshake.
    ///
    /// Returns a [`TransportConnection`] with sender, receiver, and
    /// session keys on success.
    fn connect<'a>(
        &'a self,
        params: ClientConnectParams<'a>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<TransportConnection>> + Send + 'a>>;
}

/// Server-side transport: accept connections and spawn tunnel pipelines.
///
/// Each implementation listens for incoming connections using its own
/// protocol (e.g., QUIC accept loop for MASQUE, HTTP routes for HARP)
/// and spawns a [`TunnelPipeline`] for each authenticated client.
///
/// [`TunnelPipeline`]: crate::tunnel::TunnelPipeline
///
/// # Dyn-compatibility
///
/// `run` returns a pinned boxed future so that `Box<dyn ServerTransport>`
/// works without the `async_trait` macro.
pub trait ServerTransport: Send + Sync {
    /// Human-readable transport name (e.g., `"masque"`, `"harp"`).
    fn name(&self) -> &str;

    /// Run the transport's accept loop until cancelled.
    ///
    /// Each accepted connection should authenticate the client against
    /// [`SharedServerState::registry`], create a TUN device, and spawn
    /// a tunnel pipeline task.
    fn run(
        &self,
        shared: Arc<SharedServerState>,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>>;
}

/// Shared server state accessible to all transports.
///
/// Holds transport-agnostic infrastructure that every server-side
/// transport needs: client registry, cryptographic keys, connection
/// tracking, and shutdown coordination.
///
/// `TunFactory` is NOT included because it has associated types and
/// is not dyn-compatible. Each [`ServerTransport`] implementation
/// receives its factory at construction time.
pub struct SharedServerState {
    /// Client registry for authentication and IP allocation.
    pub registry: Arc<Mutex<ClientRegistry>>,
    /// Server Noise X25519 static keypair.
    pub noise_keypair: Arc<KeyPair>,
    /// Server ML-KEM-768 key pair for post-quantum handshake.
    pub kem_keypair: Arc<KemKeyPair>,
    /// Number of currently connected VPN clients (shared across transports).
    pub active_connections: Arc<AtomicU32>,
    /// Maximum number of concurrent client connections.
    pub max_clients: u32,
    /// VPN subnet gateway IP address (first host in subnet).
    pub subnet_gateway: Ipv4Addr,
    /// Coordinated shutdown token.
    pub cancel: CancellationToken,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::noise_ik::KeyPair;
    use tokio_util::sync::CancellationToken;

    /// Noise public key length in bytes.
    const NOISE_PUB_LEN: usize = 32;

    /// AC-1: ClientConnectParams borrows keypair, server keys, and owns cancel token.
    #[test]
    fn client_connect_params_borrows_correctly() {
        let keypair = KeyPair::generate().expect("keygen");
        let server_pub = [0xAA; NOISE_PUB_LEN];
        let kem_pub = vec![0xBB; 64];
        let cancel = CancellationToken::new();

        let params = ClientConnectParams {
            noise_keypair: &keypair,
            server_noise_pub: &server_pub,
            server_kem_pub: &kem_pub,
            cancel: cancel.clone(),
        };

        assert_eq!(params.server_noise_pub, &server_pub);
        assert_eq!(params.server_kem_pub, &kem_pub[..]);
        assert!(!params.cancel.is_cancelled());
    }

    /// AC-2: TransportConnection can be constructed with mock sender/receiver.
    #[tokio::test]
    async fn transport_connection_with_mock_sender_receiver() {
        use crate::crypto::aead::KEY_LEN;
        use crate::handshake::hybrid::SessionKeys;

        struct MockSender;
        impl BoxedDatagramSender for MockSender {
            fn send_datagram(&self, _payload: &[u8]) -> Result<(), TransportError> {
                Ok(())
            }
        }

        struct MockReceiver;
        impl BoxedDatagramReceiver for MockReceiver {
            fn recv_datagram(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>> {
                Box::pin(async { Ok(vec![0xCC; 4]) })
            }
        }

        let keys = SessionKeys {
            tx_key: [0x01; KEY_LEN],
            rx_key: [0x02; KEY_LEN],
            header_key: [0x03; KEY_LEN],
        };

        let conn = TransportConnection {
            sender: Box::new(MockSender),
            receiver: Box::new(MockReceiver),
            session_keys: keys,
        };

        assert!(conn.sender.send_datagram(&[0xAA]).is_ok());
        let data = conn.receiver.recv_datagram().await.expect("recv");
        assert_eq!(data, vec![0xCC; 4]);
    }

    /// AC-5: SharedServerState can be constructed with test values.
    #[test]
    fn shared_server_state_construction() {
        use std::net::Ipv4Addr;
        use std::sync::Arc;
        use std::sync::atomic::AtomicU32;

        use crate::crypto::hybrid_kex::KemKeyPair;

        let registry = Arc::new(Mutex::new(crate::registry::ClientRegistry::new("10.0.0.0/24").expect("registry")));
        let noise_kp = Arc::new(KeyPair::generate().expect("keygen"));
        let kem_kp = Arc::new(KemKeyPair::generate());
        let cancel = CancellationToken::new();
        let max_clients: u32 = 10;
        let gateway = Ipv4Addr::new(10, 0, 0, 1);

        let state = SharedServerState {
            registry,
            noise_keypair: noise_kp,
            kem_keypair: kem_kp,
            active_connections: Arc::new(AtomicU32::new(0)),
            max_clients,
            subnet_gateway: gateway,
            cancel,
        };

        assert_eq!(state.max_clients, max_clients);
        assert_eq!(state.subnet_gateway, gateway);
        assert!(!state.cancel.is_cancelled());
    }

    /// AC-3: Box<dyn ClientTransport> compiles and can be called.
    #[tokio::test]
    async fn client_transport_trait_object_compiles() {
        struct StubTransport;
        impl ClientTransport for StubTransport {
            fn name(&self) -> &str {
                "stub"
            }
            fn connect<'a>(
                &'a self,
                _params: ClientConnectParams<'a>,
            ) -> Pin<Box<dyn Future<Output = anyhow::Result<TransportConnection>> + Send + 'a>> {
                Box::pin(async { Err(anyhow::anyhow!("not implemented")) })
            }
        }

        let transport: Box<dyn ClientTransport> = Box::new(StubTransport);
        assert_eq!(transport.name(), "stub");
    }

    /// AC-4: Box<dyn ServerTransport> compiles and can be called.
    #[tokio::test]
    async fn server_transport_trait_object_compiles() {
        struct StubServerTransport;
        impl ServerTransport for StubServerTransport {
            fn name(&self) -> &str {
                "stub-server"
            }
            fn run(
                &self,
                _shared: Arc<SharedServerState>,
                _cancel: CancellationToken,
            ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
                Box::pin(async { Ok(()) })
            }
        }

        let transport: Box<dyn ServerTransport> = Box::new(StubServerTransport);
        assert_eq!(transport.name(), "stub-server");
    }

    /// AC-5: SharedServerState fields are accessible and functional.
    #[tokio::test]
    async fn shared_server_state_fields_accessible() {
        use std::net::Ipv4Addr;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        use crate::crypto::hybrid_kex::KemKeyPair;

        let registry = Arc::new(Mutex::new(crate::registry::ClientRegistry::new("10.0.0.0/24").expect("registry")));
        let noise_kp = Arc::new(KeyPair::generate().expect("keygen"));
        let kem_kp = Arc::new(KemKeyPair::generate());
        let cancel = CancellationToken::new();
        let max_clients: u32 = 5;
        let gateway = Ipv4Addr::new(10, 0, 0, 1);
        let active = Arc::new(AtomicU32::new(0));

        let state = SharedServerState {
            registry: Arc::clone(&registry),
            noise_keypair: noise_kp,
            kem_keypair: kem_kp,
            active_connections: Arc::clone(&active),
            max_clients,
            subnet_gateway: gateway,
            cancel: cancel.clone(),
        };

        // Increment active connections
        state.active_connections.fetch_add(1, Ordering::Relaxed);
        assert_eq!(active.load(Ordering::Relaxed), 1);

        // Verify registry is accessible
        let reg = state.registry.lock().await;
        assert_eq!(reg.count(), 0);
        drop(reg);

        // Verify cancellation propagates
        cancel.cancel();
        assert!(state.cancel.is_cancelled());
    }
}
