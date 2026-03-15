// FRD: specs/frds/FRD-009.md
// FRD: specs/frds/FRD-P005.md

//! VPN server orchestrator.
//!
//! Provides [`run_multi_server`] for multi-client mode with registry-based
//! authentication, per-client tunnel pipelines, and connection limits.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::crypto::hybrid_kex::KemKeyPair;
use crate::handshake::hybrid::{HybridResponder, ResponderResult};
use crate::handshake::noise_ik::KeyPair;
use crate::registry::ClientRegistry;
use crate::transport::encrypted_channel::EncryptedChannel;
use crate::transport::masque::{MasqueProxy, build_masque_server_config};
use crate::transport::quic::generate_self_signed_cert;
use crate::tunnel::TunFactory;
use crate::tunnel::TunnelError;
use crate::tunnel::tun_device::TunDevice as _;

/// Perform the hybrid handshake as the server (responder) over MASQUE datagrams.
///
/// The handshake messages are exchanged as MASQUE datagrams:
/// 1. Receive msg1 from client
/// 2. Process msg1, generate msg2
/// 3. Send msg2 to client
async fn handshake_as_server(noise_keypair: &KeyPair, kem_keypair: KemKeyPair, proxy: &MasqueProxy) -> anyhow::Result<ResponderResult> {
    // Receive handshake message 1 from client
    let msg1 = proxy.recv_datagram().await?;
    tracing::debug!(msg1_len = msg1.len(), "received handshake msg1");

    // Process msg1 and generate msg2
    let responder = HybridResponder::new(noise_keypair, kem_keypair)?;
    let (msg2, resp_result) = responder.finish(&msg1, b"")?;

    // Send msg2 to client
    proxy.send_datagram(&msg2)?;
    tracing::debug!(msg2_len = msg2.len(), "sent handshake msg2");

    Ok(resp_result)
}

/// Configuration for the multi-client server.
pub struct MultiServerParams<F: TunFactory> {
    /// Client registry for authentication.
    pub registry: Arc<Mutex<ClientRegistry>>,
    /// Maximum number of concurrent client connections.
    pub max_clients: u32,
    /// Factory for creating per-client TUN devices.
    pub tun_factory: Arc<F>,
    /// Cancellation token for graceful shutdown.
    pub cancel: CancellationToken,
    /// Externally observable active connection counter.
    pub active_connections: Arc<AtomicU32>,
}

/// Run the VPN server in multi-client mode.
///
/// Binds QUIC on `listen_addr`, then continuously accepts connections,
/// authenticates clients against the registry, and spawns independent
/// per-client tunnel pipelines. Enforces the `max_clients` connection limit.
///
/// When `tls_cert_path` and `tls_key_path` are both `Some`, loads a CA-signed
/// PEM certificate. Otherwise falls back to generating a self-signed cert.
///
/// Returns `Ok(())` on clean shutdown (cancellation) or `Err` on bind failure.
#[allow(clippy::too_many_arguments)]
pub async fn run_multi_server<F: TunFactory>(
    listen_addr: SocketAddr,
    server_name: &str,
    noise_keypair: &KeyPair,
    kem_keypair: KemKeyPair,
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
    params: MultiServerParams<F>,
) -> anyhow::Result<()> {
    let (cert_chain, key) = match (tls_cert_path, tls_key_path) {
        (Some(cert_path), Some(key_path)) => {
            tracing::info!(cert = cert_path, key = key_path, "loading CA-signed TLS certificate");
            crate::transport::tls::load_pem_cert_and_key(std::path::Path::new(cert_path), std::path::Path::new(key_path))?
        }
        _ => {
            tracing::warn!("no TLS certificate configured, generating self-signed (not recommended for production)");
            let (cert, key) = generate_self_signed_cert(vec![server_name.to_string()])?;
            (vec![cert], key)
        }
    };
    let server_config = build_masque_server_config(cert_chain, key, 25, 300)?;

    let endpoint = quinn::Endpoint::server(server_config, listen_addr)?;
    let local_addr = endpoint.local_addr()?;
    tracing::info!("multi-client server listening on {local_addr}");

    run_multi_server_on_endpoint(endpoint, noise_keypair, kem_keypair, params).await
}

/// Run the multi-client accept loop on a pre-bound QUIC endpoint.
///
/// This is the core accept loop used by [`run_multi_server`]. It is
/// also useful for tests that need to know the actual bound address
/// before starting the server.
///
/// Each client connection is handled in a separate tokio task:
/// 1. Accept QUIC connection
/// 2. Establish MASQUE tunnel
/// 3. Perform hybrid handshake → get client's Noise static key
/// 4. Authenticate against registry
/// 5. Create per-client TUN device via factory
/// 6. Run tunnel pipeline until disconnect or cancellation
pub async fn run_multi_server_on_endpoint<F: TunFactory>(
    endpoint: quinn::Endpoint,
    noise_keypair: &KeyPair,
    kem_keypair: KemKeyPair,
    params: MultiServerParams<F>,
) -> anyhow::Result<()> {
    let MultiServerParams {
        registry,
        max_clients,
        tun_factory,
        cancel,
        active_connections,
    } = params;
    // Serialize KEM DK bytes once (KemKeyPair is not Clone)
    let kem_dk_bytes = Arc::new(kem_keypair.dk_bytes());
    let noise_private = Arc::new(noise_keypair.private_key_bytes().to_vec());
    let noise_public = *noise_keypair.public_key();

    let active_count = active_connections;
    let mut client_tasks = tokio::task::JoinSet::new();

    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => {
                match incoming {
                    Some(inc) => inc,
                    None => {
                        tracing::info!("endpoint closed");
                        break;
                    }
                }
            }
            () = cancel.cancelled() => {
                tracing::info!("shutdown signal received, stopping accept loop");
                break;
            }
        };

        let current = active_count.load(Ordering::Relaxed);
        if current >= max_clients {
            tracing::warn!(active = current, limit = max_clients, "max_clients reached, rejecting connection");
            // Drop the incoming to reject
            drop(incoming);
            continue;
        }

        // Spawn per-client handler
        let active_count = Arc::clone(&active_count);
        let kem_dk_bytes = Arc::clone(&kem_dk_bytes);
        let noise_private = Arc::clone(&noise_private);
        let registry = Arc::clone(&registry);
        let tun_factory = Arc::clone(&tun_factory);
        let client_cancel = cancel.child_token();

        active_count.fetch_add(1, Ordering::Relaxed);

        client_tasks.spawn(async move {
            // Guard: decrement active count on exit (even on panic)
            let _guard = ActiveClientGuard {
                counter: Arc::clone(&active_count),
            };

            let result = handle_client(
                incoming,
                &noise_private,
                noise_public,
                &kem_dk_bytes,
                &registry,
                &*tun_factory,
                client_cancel,
            )
            .await;

            if let Err(e) = &result {
                tracing::warn!("client handler error: {e}");
            }

            result
        });
    }

    // Wait for all active client tasks to finish
    tracing::info!(
        "waiting for {} active client(s) to disconnect",
        active_count.load(Ordering::Relaxed)
    );
    cancel.cancel(); // signal all child tokens
    while let Some(result) = client_tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::debug!("client task ended with error: {e}"),
            Err(e) => tracing::warn!("client task panicked: {e}"),
        }
    }

    endpoint.close(0u32.into(), b"shutdown");
    tracing::info!("multi-client server stopped");
    Ok(())
}

/// Handle a single client connection (runs in its own tokio task).
async fn handle_client<F: TunFactory>(
    incoming: quinn::Incoming,
    noise_private: &[u8],
    noise_public: [u8; 32],
    kem_dk_bytes: &[u8],
    registry: &Mutex<ClientRegistry>,
    tun_factory: &F,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let connection = incoming.await?;
    let remote_addr = connection.remote_address();
    tracing::info!("client connected from {remote_addr}");

    // Establish MASQUE tunnel
    let proxy = MasqueProxy::accept(connection).await?;
    tracing::debug!("MASQUE tunnel established with {remote_addr}");

    // Reconstruct keys for this handshake
    let noise_keypair = KeyPair::from_private_key(noise_private)?;
    debug_assert_eq!(noise_keypair.public_key(), &noise_public);

    let kem_keypair = KemKeyPair::from_dk_bytes(kem_dk_bytes).map_err(|e| anyhow::anyhow!("KEM key reconstruction failed: {e}"))?;

    // Perform hybrid handshake
    let resp_result = handshake_as_server(&noise_keypair, kem_keypair, &proxy).await?;
    tracing::debug!(
        "handshake complete with {:02x}{:02x}... from {remote_addr}",
        resp_result.initiator_static[0],
        resp_result.initiator_static[1]
    );

    // Authenticate against registry
    let (client_id, client_ip) = {
        let mut reg = registry.lock().await;
        match reg.authenticate(&resp_result.initiator_static) {
            Some(record) => {
                tracing::info!(
                    client_name = %record.name,
                    client_ip = %record.ip_address,
                    "client authenticated: {}",
                    record.name
                );
                (record.id, record.ip_address)
            }
            None => {
                tracing::warn!(
                    "unauthorized client {:02x}{:02x}... from {remote_addr}",
                    resp_result.initiator_static[0],
                    resp_result.initiator_static[1]
                );
                let _ = reg.log_connection_event(
                    uuid::Uuid::nil(),
                    crate::registry::ConnectionEvent::AuthFailed,
                    Some(&remote_addr.to_string()),
                    Some("unknown public key"),
                    0,
                    0,
                );
                // Send decoy response mimicking nginx web server (probe resistance)
                let decoy = crate::obfuscation::probe_resist::build_decoy_response();
                let _ = proxy.send_datagram(&decoy);
                anyhow::bail!("unauthorized client");
            }
        }
    };

    // Update last_seen and log connect event
    {
        let mut reg = registry.lock().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs();
        let _ = reg.update_last_seen(client_id, now);
        let _ = reg.log_connection_event(
            client_id,
            crate::registry::ConnectionEvent::Connect,
            Some(&remote_addr.to_string()),
            None,
            0,
            0,
        );
    }

    // Create per-client TUN device (gateway address with client as peer)
    let gateway_ip = {
        let reg = registry.lock().await;
        reg.gateway_addr()
    };
    let tun_config = crate::tunnel::TunConfig::new(gateway_ip)
        .with_destination(client_ip)
        .with_netmask(std::net::Ipv4Addr::new(255, 255, 255, 255));
    let (tun, _handle) = tun_factory
        .create_tun(&tun_config)
        .map_err(|e| anyhow::anyhow!("TUN creation failed: {e}"))?;
    tracing::info!(device = tun.name(), address = %gateway_ip, peer = %client_ip, mtu = tun.mtu(), "TUN device created for client");

    // Log QUIC datagram size budget for debugging MTU issues
    if let Some(max_dg) = proxy.max_datagram_size() {
        let overhead = crate::client::TUNNEL_OVERHEAD_BYTES;
        let safe_mtu = max_dg.saturating_sub(overhead + 4); // +4 for MASQUE framing
        tracing::info!(max_datagram_size = max_dg, overhead = overhead + 4, safe_mtu, tun_mtu = tun.mtu(), "QUIC datagram budget");
    }

    // Build encrypted channel and pipeline
    let channel = EncryptedChannel::new(resp_result.session_keys.rx_key, resp_result.session_keys.tx_key);

    let proxy = Arc::new(proxy);
    let stats = Arc::new(crate::tunnel::pipeline::TrafficStats::new());
    let pipeline = crate::tunnel::pipeline::TunnelPipeline::new(tun, channel, Arc::clone(&proxy), Arc::clone(&proxy), Arc::clone(&stats));

    tracing::info!("pipeline running for client {client_id}");
    let pipeline_result = pipeline.run(cancel).await;

    // Persist traffic stats
    {
        let sent = stats.bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
        let received = stats.bytes_received.load(std::sync::atomic::Ordering::Relaxed);
        let mut reg = registry.lock().await;
        if sent > 0 || received > 0 {
            let _ = reg.update_traffic(client_id, sent, received);
        }
        let error_msg = match &pipeline_result {
            Err(TunnelError::Cancelled) => None,
            Err(e) => Some(e.to_string()),
            Ok(()) => None,
        };
        let _ = reg.log_connection_event(
            client_id,
            crate::registry::ConnectionEvent::Disconnect,
            Some(&remote_addr.to_string()),
            error_msg.as_deref(),
            sent,
            received,
        );
    }

    match pipeline_result {
        Err(TunnelError::Cancelled) => {
            tracing::info!("pipeline cancelled for client {client_id}");
            Ok(())
        }
        Err(e) => Err(e.into()),
        Ok(()) => Ok(()),
    }
}

/// RAII guard that decrements the active client counter on drop.
struct ActiveClientGuard {
    counter: Arc<AtomicU32>,
}

impl Drop for ActiveClientGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Return the local address of a QUIC server endpoint.
///
/// Useful for tests that bind to `:0` and need the actual port.
pub fn bind_ephemeral_server(server_name: &str) -> anyhow::Result<(quinn::Endpoint, SocketAddr)> {
    let (cert, key) = generate_self_signed_cert(vec![server_name.to_string()])?;
    let server_config = build_masque_server_config(vec![cert], key, 25, 300)?;
    let addr: SocketAddr = "127.0.0.1:0".parse()?;
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    let local_addr = endpoint.local_addr()?;
    Ok((endpoint, local_addr))
}

// ---------------------------------------------------------------------------
// MASQUE Server Transport Adapter (Step 11)
// ---------------------------------------------------------------------------

use crate::transport::traits::{ServerTransport, SharedServerState};

/// Human-readable name for the MASQUE server transport.
const MASQUE_SERVER_TRANSPORT_NAME: &str = "masque";

/// MASQUE server transport implementing [`ServerTransport`].
///
/// Wraps the existing QUIC/MASQUE accept loop (`run_multi_server_on_endpoint`)
/// behind the pluggable transport trait interface. Holds a generic
/// `TunFactory` for creating per-client TUN devices.
pub struct MasqueServerTransport<F: TunFactory> {
    /// Server listen address for QUIC (UDP).
    listen_addr: SocketAddr,
    /// Server name for TLS certificate generation.
    server_name: String,
    /// Optional path to a PEM TLS certificate.
    tls_cert_path: Option<String>,
    /// Optional path to a PEM TLS private key.
    tls_key_path: Option<String>,
    /// Factory for creating per-client TUN devices.
    tun_factory: Arc<F>,
}

impl<F: TunFactory> MasqueServerTransport<F> {
    /// Create a new MASQUE server transport with the given configuration.
    pub fn new(
        listen_addr: SocketAddr,
        server_name: String,
        tls_cert_path: Option<String>,
        tls_key_path: Option<String>,
        tun_factory: Arc<F>,
    ) -> Self {
        Self {
            listen_addr,
            server_name,
            tls_cert_path,
            tls_key_path,
            tun_factory,
        }
    }
}

impl<F: TunFactory + 'static> ServerTransport for MasqueServerTransport<F>
where
    F::Tun: 'static,
    F::Handle: 'static,
{
    fn name(&self) -> &str {
        MASQUE_SERVER_TRANSPORT_NAME
    }

    fn run(
        &self,
        shared: Arc<SharedServerState>,
        cancel: CancellationToken,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(async move {
            let noise_keypair = KeyPair::from_private_key(shared.noise_keypair.private_key_bytes())?;
            let kem_keypair =
                KemKeyPair::from_dk_bytes(&shared.kem_keypair.dk_bytes()).map_err(|e| anyhow::anyhow!("KEM key reconstruction: {e}"))?;

            let params = MultiServerParams {
                registry: Arc::clone(&shared.registry),
                max_clients: shared.max_clients,
                tun_factory: Arc::clone(&self.tun_factory),
                cancel: cancel.clone(),
                active_connections: Arc::clone(&shared.active_connections),
            };

            run_multi_server(
                self.listen_addr,
                &self.server_name,
                &noise_keypair,
                kem_keypair,
                self.tls_cert_path.as_deref(),
                self.tls_key_path.as_deref(),
                params,
            )
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::MockTun;
    use crate::tunnel::tun_device::{DEFAULT_TUNNEL_MTU, TunDevice};

    const TEST_SERVER_NAME: &str = "localhost";
    const TEST_LISTEN_ADDR: &str = "127.0.0.1:0";
    const TEST_TIMEOUT_SECS: u64 = 10;

    // FRD: specs/frds/FRD-P005.md

    const TEST_SUBNET: &str = "10.66.66.0/24";
    const TEST_MAX_CLIENTS: u32 = 3;

    /// Install the rustls ring crypto provider (idempotent — safe to call multiple times).
    fn init_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// Helper: register a client in the registry using the given KeyPair.
    fn register_client(registry: &mut ClientRegistry, name: &str, keypair: &KeyPair) {
        registry.add(name, *keypair.public_key(), None).expect("register client");
    }

    // AC-6: TunFactory trait creates per-client TUN
    #[test]
    fn tun_factory_creates_tun() {
        use crate::tunnel::MockTunFactory;
        use crate::tunnel::TunConfig;
        use crate::tunnel::TunFactory as _;

        let factory = MockTunFactory::new(DEFAULT_TUNNEL_MTU);
        let config = TunConfig::new(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let (tun, _handle) = factory.create_tun(&config).expect("create tun");
        assert_eq!(tun.mtu(), DEFAULT_TUNNEL_MTU);
        assert_eq!(tun.name(), "mock0");

        // Each call creates a new independent device
        let (tun2, _handle2) = factory.create_tun(&config).expect("create tun 2");
        assert_eq!(tun2.mtu(), DEFAULT_TUNNEL_MTU);
    }

    /// Helper: create a test harness with pre-bound endpoint.
    struct TestHarness {
        endpoint: quinn::Endpoint,
        actual_addr: SocketAddr,
        server_noise: KeyPair,
        server_kem: KemKeyPair,
        server_noise_pub: [u8; 32],
        server_kem_pub: Vec<u8>,
    }

    impl TestHarness {
        fn new() -> Self {
            init_crypto_provider();
            let server_noise = KeyPair::generate().expect("server noise keypair");
            let server_kem = KemKeyPair::generate();
            let server_kem_pub = server_kem.encapsulation_key_bytes();
            let server_noise_pub = *server_noise.public_key();

            let (cert, key) = generate_self_signed_cert(vec![TEST_SERVER_NAME.to_string()]).expect("cert");
            let server_config = build_masque_server_config(vec![cert], key, 25, 300).expect("server config");
            let listen_addr: SocketAddr = TEST_LISTEN_ADDR.parse().expect("valid addr");
            let endpoint = quinn::Endpoint::server(server_config, listen_addr).expect("server bind");
            let actual_addr = endpoint.local_addr().expect("local addr");

            Self {
                endpoint,
                actual_addr,
                server_noise,
                server_kem,
                server_noise_pub,
                server_kem_pub,
            }
        }
    }

    // AC-5 / T-P005-5: Graceful shutdown of multi-client server with no active clients
    #[tokio::test]
    async fn multi_client_graceful_shutdown() {
        use crate::tunnel::MockTunFactory;

        let harness = TestHarness::new();

        let registry = ClientRegistry::new(TEST_SUBNET).expect("create registry");
        let registry = Arc::new(Mutex::new(registry));
        let tun_factory = Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU));

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let server_task = tokio::spawn(async move {
            run_multi_server_on_endpoint(
                harness.endpoint,
                &harness.server_noise,
                harness.server_kem,
                MultiServerParams {
                    registry,
                    max_clients: TEST_MAX_CLIENTS,
                    tun_factory,
                    cancel: cancel_clone,
                    active_connections: Arc::new(AtomicU32::new(0)),
                },
            )
            .await
        });

        // Let server start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Cancel before any client connects
        cancel.cancel();

        let result = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), server_task)
            .await
            .expect("server should stop within timeout")
            .expect("task join");

        assert!(result.is_ok(), "multi-server should shut down cleanly: {result:?}");
    }

    // AC-1 / T-P005-1: Server accepts multiple concurrent connections
    // AC-2 / T-P005-2: Each client gets independent handshake and pipeline
    #[tokio::test]
    async fn multi_client_two_simultaneous() {
        use crate::tunnel::MockTunFactory;

        let harness = TestHarness::new();
        let actual_addr = harness.actual_addr;
        let server_noise_pub = harness.server_noise_pub;
        let server_kem_pub = harness.server_kem_pub.clone();

        let mut registry = ClientRegistry::new(TEST_SUBNET).expect("create registry");

        // Register two clients
        let client1_noise = KeyPair::generate().expect("client1 noise keypair");
        let client2_noise = KeyPair::generate().expect("client2 noise keypair");
        register_client(&mut registry, "client-1", &client1_noise);
        register_client(&mut registry, "client-2", &client2_noise);

        let registry = Arc::new(Mutex::new(registry));
        let tun_factory = Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU));

        let cancel = CancellationToken::new();

        let server_task = {
            let cancel = cancel.clone();
            let registry = Arc::clone(&registry);
            let tun_factory = Arc::clone(&tun_factory);
            tokio::spawn(async move {
                run_multi_server_on_endpoint(
                    harness.endpoint,
                    &harness.server_noise,
                    harness.server_kem,
                    MultiServerParams {
                        registry,
                        max_clients: TEST_MAX_CLIENTS,
                        tun_factory,
                        cancel,
                        active_connections: Arc::new(AtomicU32::new(0)),
                    },
                )
                .await
            })
        };

        // Connect client 1
        let (client1_tun, _client1_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let client1_cancel = cancel.child_token();
        let kem_pub_clone = server_kem_pub.clone();
        let client1_task = tokio::spawn(async move {
            crate::client::run_client(
                actual_addr,
                TEST_SERVER_NAME,
                &client1_noise,
                &server_noise_pub,
                &kem_pub_clone,
                client1_tun,
                25,
                300,
                true,
                client1_cancel,
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Connect client 2
        let (client2_tun, _client2_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let client2_cancel = cancel.child_token();
        let client2_task = tokio::spawn(async move {
            crate::client::run_client(
                actual_addr,
                TEST_SERVER_NAME,
                &client2_noise,
                &server_noise_pub,
                &server_kem_pub,
                client2_tun,
                25,
                300,
                true,
                client2_cancel,
            )
            .await
        });

        // Let client 2 establish pipeline
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Both clients should be authenticated — verify last_seen updated
        {
            let reg = registry.lock().await;
            let clients = reg.list();
            assert_eq!(clients.len(), 2, "both clients should be in registry");
            for c in &clients {
                assert!(c.last_seen.is_some(), "client {} should have last_seen set", c.name);
            }
        }

        // Clean shutdown
        cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), server_task).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), client1_task).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), client2_task).await;
    }

    // AC-3 / T-P005-3: max_clients limit rejects connections at capacity
    #[tokio::test]
    async fn multi_client_max_clients_enforced() {
        use crate::tunnel::MockTunFactory;

        let harness = TestHarness::new();
        let actual_addr = harness.actual_addr;
        let server_noise_pub = harness.server_noise_pub;
        let server_kem_pub = harness.server_kem_pub.clone();

        let max_clients_limit: u32 = 1;
        let mut registry = ClientRegistry::new(TEST_SUBNET).expect("create registry");

        let client1_noise = KeyPair::generate().expect("client1 noise keypair");
        let client1_pub = *client1_noise.public_key();
        let client2_noise = KeyPair::generate().expect("client2 noise keypair");
        register_client(&mut registry, "client-1", &client1_noise);
        register_client(&mut registry, "client-2", &client2_noise);

        let registry = Arc::new(Mutex::new(registry));
        let tun_factory = Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU));

        let cancel = CancellationToken::new();

        let server_task = {
            let cancel = cancel.clone();
            let registry = Arc::clone(&registry);
            let tun_factory = Arc::clone(&tun_factory);
            tokio::spawn(async move {
                run_multi_server_on_endpoint(
                    harness.endpoint,
                    &harness.server_noise,
                    harness.server_kem,
                    MultiServerParams {
                        registry,
                        max_clients: max_clients_limit,
                        tun_factory,
                        cancel,
                        active_connections: Arc::new(AtomicU32::new(0)),
                    },
                )
                .await
            })
        };

        // Connect client 1 — should succeed (fills the 1 slot)
        let (client1_tun, _client1_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let client1_cancel = cancel.child_token();
        let kem_pub_clone = server_kem_pub.clone();
        let client1_task = tokio::spawn(async move {
            crate::client::run_client(
                actual_addr,
                TEST_SERVER_NAME,
                &client1_noise,
                &server_noise_pub,
                &kem_pub_clone,
                client1_tun,
                25,
                300,
                true,
                client1_cancel,
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Client 1 should be connected
        {
            let reg = registry.lock().await;
            let c1 = reg.get_by_public_key(&client1_pub);
            assert!(c1.is_some(), "client-1 should be in registry");
        }

        // Connect client 2 — should be rejected (at capacity)
        let (client2_tun, _client2_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let client2_cancel = cancel.child_token();
        let client2_task = tokio::spawn(async move {
            crate::client::run_client(
                actual_addr,
                TEST_SERVER_NAME,
                &client2_noise,
                &server_noise_pub,
                &server_kem_pub,
                client2_tun,
                25,
                300,
                true,
                client2_cancel,
            )
            .await
        });

        // Client 2 should fail within timeout (connection rejected)
        let client2_result = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), client2_task)
            .await
            .expect("client2 should resolve within timeout")
            .expect("client2 task join");

        assert!(client2_result.is_err(), "client2 should fail because max_clients reached");

        // Clean shutdown
        cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), server_task).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), client1_task).await;
    }

    // AC-4 / T-P005-4: Client disconnect doesn't affect other clients
    #[tokio::test]
    async fn multi_client_disconnect_isolation() {
        use crate::tunnel::MockTunFactory;

        let harness = TestHarness::new();
        let actual_addr = harness.actual_addr;
        let server_noise_pub = harness.server_noise_pub;
        let server_kem_pub = harness.server_kem_pub.clone();

        let mut registry = ClientRegistry::new(TEST_SUBNET).expect("create registry");

        let client1_noise = KeyPair::generate().expect("client1 noise keypair");
        let client2_noise = KeyPair::generate().expect("client2 noise keypair");
        register_client(&mut registry, "client-1", &client1_noise);
        register_client(&mut registry, "client-2", &client2_noise);

        let registry = Arc::new(Mutex::new(registry));
        let tun_factory = Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU));

        let cancel = CancellationToken::new();

        let server_task = {
            let cancel = cancel.clone();
            let registry = Arc::clone(&registry);
            let tun_factory = Arc::clone(&tun_factory);
            tokio::spawn(async move {
                run_multi_server_on_endpoint(
                    harness.endpoint,
                    &harness.server_noise,
                    harness.server_kem,
                    MultiServerParams {
                        registry,
                        max_clients: TEST_MAX_CLIENTS,
                        tun_factory,
                        cancel,
                        active_connections: Arc::new(AtomicU32::new(0)),
                    },
                )
                .await
            })
        };

        // Connect client 1 with its own cancel token
        let client1_cancel = CancellationToken::new();
        let (client1_tun, _client1_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let kem_pub_clone = server_kem_pub.clone();
        let client1_cancel_clone = client1_cancel.clone();
        let client1_task = tokio::spawn(async move {
            crate::client::run_client(
                actual_addr,
                TEST_SERVER_NAME,
                &client1_noise,
                &server_noise_pub,
                &kem_pub_clone,
                client1_tun,
                25,
                300,
                true,
                client1_cancel_clone,
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Connect client 2 with its own cancel token
        let client2_cancel = CancellationToken::new();
        let (client2_tun, _client2_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let client2_cancel_clone = client2_cancel.clone();
        let client2_task = tokio::spawn(async move {
            crate::client::run_client(
                actual_addr,
                TEST_SERVER_NAME,
                &client2_noise,
                &server_noise_pub,
                &server_kem_pub,
                client2_tun,
                25,
                300,
                true,
                client2_cancel_clone,
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Disconnect client 1
        client1_cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), client1_task).await;

        // Give server time to clean up client 1
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Server should still be running (not cancelled)
        assert!(
            !server_task.is_finished(),
            "server should still be running after client 1 disconnect"
        );

        // Clean shutdown
        client2_cancel.cancel();
        cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), server_task).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), client2_task).await;
    }

    // T-P005-6: Unauthorized client (not in registry) is rejected
    #[tokio::test]
    async fn multi_client_unauthorized_rejected() {
        use crate::tunnel::MockTunFactory;

        let harness = TestHarness::new();
        let actual_addr = harness.actual_addr;
        let server_noise_pub = harness.server_noise_pub;
        let server_kem_pub = harness.server_kem_pub.clone();

        // Empty registry — no clients registered
        let registry = ClientRegistry::new(TEST_SUBNET).expect("create registry");
        let registry = Arc::new(Mutex::new(registry));
        let tun_factory = Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU));

        let cancel = CancellationToken::new();

        let server_task = {
            let cancel = cancel.clone();
            let registry = Arc::clone(&registry);
            let tun_factory = Arc::clone(&tun_factory);
            tokio::spawn(async move {
                run_multi_server_on_endpoint(
                    harness.endpoint,
                    &harness.server_noise,
                    harness.server_kem,
                    MultiServerParams {
                        registry,
                        max_clients: TEST_MAX_CLIENTS,
                        tun_factory,
                        cancel,
                        active_connections: Arc::new(AtomicU32::new(0)),
                    },
                )
                .await
            })
        };

        // Connect an unregistered client
        let rogue_noise = KeyPair::generate().expect("rogue noise keypair");
        let (rogue_tun, _rogue_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let rogue_cancel = cancel.child_token();
        let rogue_task = tokio::spawn(async move {
            crate::client::run_client(
                actual_addr,
                TEST_SERVER_NAME,
                &rogue_noise,
                &server_noise_pub,
                &server_kem_pub,
                rogue_tun,
                25,
                300,
                true,
                rogue_cancel,
            )
            .await
        });

        // Rogue client should fail (unauthorized)
        let rogue_result = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), rogue_task)
            .await
            .expect("rogue should resolve within timeout")
            .expect("rogue task join");

        assert!(rogue_result.is_err(), "rogue client should be rejected by server");

        // Server should still be running
        assert!(!server_task.is_finished(), "server should still be running after rejecting rogue");

        cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), server_task).await;
    }

    // T-P005-7: ActiveClientGuard decrements counter on drop
    #[test]
    fn active_client_guard_decrements_on_drop() {
        let counter = Arc::new(AtomicU32::new(1));
        let guard = ActiveClientGuard {
            counter: Arc::clone(&counter),
        };
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        drop(guard);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    // FRD: specs/frds/FRD-P003.md
    // T-P003-14: Integration — KeyStore keys → base64 resolution → client connects
    #[tokio::test]
    async fn integration_keystore_to_client_round_trip() {
        use crate::config::{resolve_server_kem_key, resolve_server_noise_key};
        use crate::keys::KeyStore;
        use crate::tunnel::MockTunFactory;

        init_crypto_provider();

        // Server generates keys via KeyStore (in-memory, no disk)
        let key_store = KeyStore::generate().expect("generate key store");
        let noise_b64 = key_store.noise_public_key_base64();
        let kem_b64 = key_store.kem_public_key_base64();

        // Client resolves keys from "CLI flags" (base64 strings)
        let server_noise_pub = resolve_server_noise_key(Some(&noise_b64), None).expect("resolve noise key");
        let server_kem_pub = resolve_server_kem_key(Some(&kem_b64), None).expect("resolve kem key");

        // Verify resolved keys match KeyStore originals
        assert_eq!(&server_noise_pub, key_store.noise_keypair().public_key());
        assert_eq!(server_kem_pub, key_store.kem_keypair().encapsulation_key_bytes());

        // Build server endpoint using KeyStore keys
        let (server_noise, server_kem) = key_store.into_parts();
        let (cert, key) = generate_self_signed_cert(vec![TEST_SERVER_NAME.to_string()]).expect("cert");
        let server_config = build_masque_server_config(vec![cert], key, 25, 300).expect("server config");
        let listen_addr: SocketAddr = TEST_LISTEN_ADDR.parse().expect("valid addr");
        let endpoint = quinn::Endpoint::server(server_config, listen_addr).expect("server bind");
        let actual_addr = endpoint.local_addr().expect("local addr");

        // Register a client in the registry
        let client_noise = KeyPair::generate().expect("client noise keypair");
        let mut registry = ClientRegistry::new(TEST_SUBNET).expect("create registry");
        register_client(&mut registry, "keystore-test-client", &client_noise);
        let registry = Arc::new(Mutex::new(registry));
        let tun_factory = Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU));

        let cancel = CancellationToken::new();

        let server_task = {
            let cancel = cancel.clone();
            let registry = Arc::clone(&registry);
            let tun_factory = Arc::clone(&tun_factory);
            tokio::spawn(async move {
                run_multi_server_on_endpoint(
                    endpoint,
                    &server_noise,
                    server_kem,
                    MultiServerParams {
                        registry,
                        max_clients: TEST_MAX_CLIENTS,
                        tun_factory,
                        cancel,
                        active_connections: Arc::new(AtomicU32::new(0)),
                    },
                )
                .await
            })
        };

        // Connect using the registered client's keypair
        let (client_tun, _client_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let client_cancel = cancel.child_token();
        let client_task = tokio::spawn(async move {
            crate::client::run_client(
                actual_addr,
                TEST_SERVER_NAME,
                &client_noise,
                &server_noise_pub,
                &server_kem_pub,
                client_tun,
                25,
                300,
                true,
                client_cancel,
            )
            .await
        });

        // Let pipeline establish
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Verify client was authenticated (last_seen set)
        {
            let reg = registry.lock().await;
            let clients = reg.list();
            assert_eq!(clients.len(), 1, "one client should be in registry");
            assert!(
                clients[0].last_seen.is_some(),
                "client should have last_seen set after authentication"
            );
        }

        // Clean shutdown
        cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), server_task).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), client_task).await;
    }

    // T-P005-R3: Load test — 10 concurrent clients with MockTun
    #[tokio::test]
    async fn load_test_ten_concurrent_clients() {
        use crate::tunnel::MockTunFactory;

        let load_client_count: usize = 10;
        let stagger_delay_ms: u64 = 100;
        let settle_delay_ms: u64 = 2000;

        let harness = TestHarness::new();
        let actual_addr = harness.actual_addr;
        let server_noise_pub = harness.server_noise_pub;
        let server_kem_pub = harness.server_kem_pub.clone();

        let mut registry = ClientRegistry::new(TEST_SUBNET).expect("create registry");

        // Register 10 clients
        let mut keypairs = Vec::new();
        for i in 0..load_client_count {
            let kp = KeyPair::generate().expect("keypair");
            register_client(&mut registry, &format!("load-client-{i}"), &kp);
            keypairs.push(kp);
        }

        let registry = Arc::new(Mutex::new(registry));
        let tun_factory = Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU));
        let active_connections = Arc::new(AtomicU32::new(0));
        let cancel = CancellationToken::new();

        let server_task = {
            let cancel = cancel.clone();
            let registry = Arc::clone(&registry);
            let tun_factory = Arc::clone(&tun_factory);
            let active_connections = Arc::clone(&active_connections);
            tokio::spawn(async move {
                run_multi_server_on_endpoint(
                    harness.endpoint,
                    &harness.server_noise,
                    harness.server_kem,
                    MultiServerParams {
                        registry,
                        max_clients: load_client_count as u32,
                        tun_factory,
                        cancel,
                        active_connections,
                    },
                )
                .await
            })
        };

        // Connect 10 clients with stagger
        let mut client_tasks = Vec::new();
        // Store private key bytes for reconstruction in spawned tasks
        let private_keys: Vec<Vec<u8>> = keypairs.iter().map(|kp| kp.private_key_bytes().to_vec()).collect();

        let mut tun_handles = Vec::new();
        for pk_bytes in &private_keys {
            let (tun, handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
            tun_handles.push(handle);
            let client_cancel = cancel.child_token();
            let noise_pub = server_noise_pub;
            let kem_pub = server_kem_pub.clone();
            let pk = pk_bytes.clone();
            let task = tokio::spawn(async move {
                let kp = KeyPair::from_private_key(&pk).expect("reconstruct keypair");
                crate::client::run_client(
                    actual_addr,
                    TEST_SERVER_NAME,
                    &kp,
                    &noise_pub,
                    &kem_pub,
                    tun,
                    25,
                    300,
                    true,
                    client_cancel,
                )
                .await
            });
            client_tasks.push(task);
            tokio::time::sleep(std::time::Duration::from_millis(stagger_delay_ms)).await;
        }

        // Allow all to establish
        tokio::time::sleep(std::time::Duration::from_millis(settle_delay_ms)).await;

        // Verify all connected
        {
            let reg = registry.lock().await;
            let clients = reg.list();
            let connected_count = clients.iter().filter(|c| c.last_seen.is_some()).count();
            assert_eq!(connected_count, load_client_count, "all 10 clients should have last_seen set");
        }

        assert_eq!(
            active_connections.load(Ordering::Relaxed),
            load_client_count as u32,
            "active connection counter should be 10"
        );

        // Clean shutdown
        drop(tun_handles);
        cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), server_task).await;
        for task in client_tasks {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), task).await;
        }
    }

    // T-E2E-DATA: Full client→server→client data flow through encrypted tunnel.
    //
    // Verifies that a packet injected into the client's MockTun traverses the
    // full stack (TUN → encrypt → MASQUE → network → MASQUE → decrypt → TUN)
    // and arrives at the server's MockTun, and vice versa.
    #[tokio::test]
    async fn e2e_data_flow_through_tunnel() {
        use crate::tunnel::CapturingMockTunFactory;

        let data_settle_ms: u64 = 500;
        let data_timeout_secs: u64 = 3;

        let harness = TestHarness::new();
        let actual_addr = harness.actual_addr;
        let server_noise_pub = harness.server_noise_pub;
        let server_kem_pub = harness.server_kem_pub.clone();

        let mut registry = ClientRegistry::new(TEST_SUBNET).expect("create registry");
        let client_noise = KeyPair::generate().expect("client noise keypair");
        register_client(&mut registry, "data-test-client", &client_noise);

        let registry = Arc::new(Mutex::new(registry));
        // Use CapturingMockTunFactory to get server-side TUN handles.
        let tun_factory = Arc::new(CapturingMockTunFactory::new(DEFAULT_TUNNEL_MTU));
        let cancel = CancellationToken::new();

        let server_task = {
            let cancel = cancel.clone();
            let registry = Arc::clone(&registry);
            let tun_factory = Arc::clone(&tun_factory);
            tokio::spawn(async move {
                run_multi_server_on_endpoint(
                    harness.endpoint,
                    &harness.server_noise,
                    harness.server_kem,
                    MultiServerParams {
                        registry,
                        max_clients: TEST_MAX_CLIENTS,
                        tun_factory,
                        cancel,
                        active_connections: Arc::new(AtomicU32::new(0)),
                    },
                )
                .await
            })
        };

        // Connect client — keep the client-side TUN handle for injection.
        let (client_tun, client_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let client_cancel = cancel.child_token();
        let client_task = tokio::spawn(async move {
            crate::client::run_client(
                actual_addr,
                TEST_SERVER_NAME,
                &client_noise,
                &server_noise_pub,
                &server_kem_pub,
                client_tun,
                25,
                300,
                true,
                client_cancel,
            )
            .await
        });

        // Wait for connection + handshake + pipeline start.
        tokio::time::sleep(std::time::Duration::from_millis(data_settle_ms)).await;

        // Retrieve the server-side TUN handle.
        let server_handles = tun_factory.take_handles();
        assert_eq!(server_handles.len(), 1, "server should have created exactly one TUN");
        let server_handle = &server_handles[0];

        // --- Client → Server: inject packet on client TUN, capture on server TUN ---
        let client_to_server_payload = b"hello-from-client-e2e";
        client_handle
            .inject_packet(client_to_server_payload)
            .await
            .expect("inject into client TUN");

        let captured = tokio::time::timeout(std::time::Duration::from_secs(data_timeout_secs), server_handle.capture_packet())
            .await
            .expect("timeout waiting for server capture")
            .expect("server capture returned None");

        assert_eq!(
            captured, client_to_server_payload,
            "packet from client should arrive at server TUN unmodified"
        );

        // --- Server → Client: inject packet on server TUN, capture on client TUN ---
        let server_to_client_payload = b"reply-from-server-e2e";
        server_handle
            .inject_packet(server_to_client_payload)
            .await
            .expect("inject into server TUN");

        let captured = tokio::time::timeout(std::time::Duration::from_secs(data_timeout_secs), client_handle.capture_packet())
            .await
            .expect("timeout waiting for client capture")
            .expect("client capture returned None");

        assert_eq!(
            captured, server_to_client_payload,
            "packet from server should arrive at client TUN unmodified"
        );

        // Clean shutdown.
        drop(server_handles);
        cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), server_task).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), client_task).await;
    }

    // FRD: specs/frds/FRD-20260223-masque-transport-traits.md
    // T-S11-1: MasqueServerTransport::name() returns "masque"
    #[test]
    fn masque_server_transport_name() {
        use crate::transport::traits::ServerTransport;
        use crate::tunnel::MockTunFactory;
        use crate::tunnel::tun_device::DEFAULT_TUNNEL_MTU;

        let transport = MasqueServerTransport::new(
            TEST_LISTEN_ADDR.parse().expect("valid addr"),
            TEST_SERVER_NAME.to_string(),
            None,
            None,
            Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU)),
        );

        assert_eq!(transport.name(), MASQUE_SERVER_TRANSPORT_NAME);
    }

    // T-S11-2: MasqueServerTransport can be used as Box<dyn ServerTransport>
    #[test]
    fn masque_server_transport_trait_object() {
        use crate::transport::traits::ServerTransport;
        use crate::tunnel::MockTunFactory;
        use crate::tunnel::tun_device::DEFAULT_TUNNEL_MTU;

        let transport: Box<dyn ServerTransport> = Box::new(MasqueServerTransport::new(
            TEST_LISTEN_ADDR.parse().expect("valid addr"),
            TEST_SERVER_NAME.to_string(),
            None,
            None,
            Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU)),
        ));

        assert_eq!(transport.name(), MASQUE_SERVER_TRANSPORT_NAME);
    }

    // T-S11-3: MasqueServerTransport::run() starts and shuts down cleanly
    #[tokio::test]
    async fn masque_server_transport_run_shutdown() {
        use crate::transport::traits::{ServerTransport, SharedServerState};
        use crate::tunnel::MockTunFactory;
        use crate::tunnel::tun_device::DEFAULT_TUNNEL_MTU;

        init_crypto_provider();

        let noise_kp = Arc::new(KeyPair::generate().expect("noise keypair"));
        let kem_kp = Arc::new(KemKeyPair::generate());
        let registry = Arc::new(tokio::sync::Mutex::new(ClientRegistry::new(TEST_SUBNET).expect("registry")));
        let cancel = CancellationToken::new();

        let shared = Arc::new(SharedServerState {
            registry,
            noise_keypair: noise_kp,
            kem_keypair: kem_kp,
            active_connections: Arc::new(AtomicU32::new(0)),
            max_clients: TEST_MAX_CLIENTS,
            subnet_gateway: std::net::Ipv4Addr::new(10, 66, 66, 1),
            cancel: cancel.clone(),
        });

        let transport = MasqueServerTransport::new(
            TEST_LISTEN_ADDR.parse().expect("valid addr"),
            TEST_SERVER_NAME.to_string(),
            None,
            None,
            Arc::new(MockTunFactory::new(DEFAULT_TUNNEL_MTU)),
        );

        let cancel_clone = cancel.clone();
        let server_task = tokio::spawn(async move { transport.run(shared, cancel_clone).await });

        // Let server bind and start accept loop
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Cancel before any client connects
        cancel.cancel();

        let result = tokio::time::timeout(std::time::Duration::from_secs(TEST_TIMEOUT_SECS), server_task)
            .await
            .expect("server should stop within timeout")
            .expect("task join");

        assert!(result.is_ok(), "transport should shut down cleanly: {result:?}");
    }
}
