// FRD: specs/frds/FRD-009.md

//! VPN client orchestrator.
//!
//! Connects to a QUIC server, performs the hybrid Noise IK + ML-KEM-768
//! handshake, establishes a MASQUE CONNECT-UDP tunnel, and runs the
//! bidirectional packet pipeline until cancelled.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::handshake::hybrid::{HybridInitiator, InitiatorResult};
use crate::handshake::noise_ik::KeyPair;
use crate::transport::encrypted_channel::EncryptedChannel;
use crate::transport::masque::{MasqueClient, build_masque_client_config};
use crate::tunnel::TunnelError;
use crate::tunnel::tun_device::TunDevice;

/// Run the VPN client.
///
/// Connects to the server at `server_addr`, performs the hybrid handshake,
/// establishes the MASQUE tunnel, and runs the packet pipeline with the
/// given TUN device until `cancel` is triggered.
///
/// `server_noise_pub` is the server's known Noise static public key.
/// `server_kem_pub` is the server's ML-KEM-768 encapsulation key bytes.
///
/// Returns `Ok(())` on clean shutdown (cancellation) or `Err` on failure.
#[allow(clippy::too_many_arguments)]
pub async fn run_client<T: TunDevice>(
    server_addr: SocketAddr,
    server_name: &str,
    noise_keypair: &KeyPair,
    server_noise_pub: &[u8; 32],
    server_kem_pub: &[u8],
    tun: T,
    keep_alive_interval: u64,
    max_idle_timeout: u64,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    // Build MASQUE-enabled client config
    let client_config = build_masque_client_config(keep_alive_interval, max_idle_timeout)?;

    // Create QUIC client endpoint
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
    endpoint.set_default_client_config(client_config);

    tracing::info!("connecting to {server_addr}");

    // Connect to server
    let connection = endpoint.connect(server_addr, server_name)?.await?;
    tracing::info!("QUIC connection established to {server_addr}");

    // Establish MASQUE CONNECT-UDP tunnel
    let masque_client = MasqueClient::connect(connection).await?;
    tracing::info!("MASQUE tunnel established");

    // Perform hybrid handshake over MASQUE datagrams
    let init_result = handshake_as_client(noise_keypair, server_noise_pub, server_kem_pub, &masque_client).await?;
    tracing::info!("hybrid handshake complete");

    // Create encrypted channel (client is initiator: tx_key = tx, rx_key = rx)
    let channel = EncryptedChannel::new(init_result.session_keys.tx_key, init_result.session_keys.rx_key);

    // Build and run the pipeline
    let masque_client = Arc::new(masque_client);
    let stats = Arc::new(crate::tunnel::pipeline::TrafficStats::new());
    let pipeline =
        crate::tunnel::pipeline::TunnelPipeline::new(tun, channel, Arc::clone(&masque_client), Arc::clone(&masque_client), stats);

    tracing::info!("tunnel pipeline running");
    match pipeline.run(cancel.clone()).await {
        Err(TunnelError::Cancelled) => {
            tracing::info!("tunnel pipeline cancelled — shutting down");
            Ok(())
        }
        Err(e) => Err(e.into()),
        Ok(()) => Ok(()),
    }
}

/// Perform the hybrid handshake as the client (initiator) over MASQUE datagrams.
///
/// The handshake messages are exchanged as MASQUE datagrams:
/// 1. Create initiator, generate msg1
/// 2. Send msg1 to server
/// 3. Receive msg2 from server
/// 4. Finalize handshake
async fn handshake_as_client(
    noise_keypair: &KeyPair,
    server_noise_pub: &[u8; 32],
    server_kem_pub: &[u8],
    masque_client: &MasqueClient,
) -> anyhow::Result<InitiatorResult> {
    // Create initiator and generate msg1
    let (initiator, msg1) = HybridInitiator::new(noise_keypair, server_noise_pub, server_kem_pub)?;
    tracing::debug!(msg1_len = msg1.len(), "sending handshake msg1");

    // Send msg1 to server
    masque_client.send_datagram(&msg1)?;

    // Receive msg2 from server
    let msg2 = masque_client.recv_datagram().await?;
    tracing::debug!(msg2_len = msg2.len(), "received handshake msg2");

    // Finalize handshake
    let result = initiator.finish(&msg2)?;

    Ok(result)
}
