// FRD: specs/frds/FRD-008.md

//! Packet pipeline: TUN ↔ EncryptedChannel ↔ MASQUE.
//!
//! [`TunnelPipeline`] drives two concurrent loops:
//! - **Inbound**: TUN recv → encrypt → MASQUE send_datagram
//! - **Outbound**: MASQUE recv_datagram → decrypt → TUN send
//!
//! The pipeline runs until the cancellation token is triggered or an error occurs.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio_util::sync::CancellationToken;

use crate::transport::encrypted_channel::EncryptedChannel;
use crate::transport::masque::{MasqueClient, MasqueProxy};

use super::TunnelError;
use super::tun_device::TunDevice;

/// Maximum buffer size for reading IP packets from the TUN device.
/// Slightly larger than MAX_TUNNEL_MTU to detect oversized packets.
const TUN_READ_BUF_SIZE: usize = 2048;

/// Trait for sending datagrams through the MASQUE tunnel.
///
/// Implemented by both [`MasqueClient`] and [`MasqueProxy`].
pub trait DatagramSender: Send + Sync {
    /// Send a datagram payload through the MASQUE tunnel.
    fn send_datagram(&self, payload: &[u8]) -> Result<(), crate::transport::TransportError>;
}

/// Trait for receiving datagrams from the MASQUE tunnel.
///
/// Implemented by both [`MasqueClient`] and [`MasqueProxy`].
pub trait DatagramReceiver: Send + Sync {
    /// Receive a datagram payload from the MASQUE tunnel.
    fn recv_datagram(&self) -> impl std::future::Future<Output = Result<Vec<u8>, crate::transport::TransportError>> + Send;
}

impl DatagramSender for MasqueClient {
    fn send_datagram(&self, payload: &[u8]) -> Result<(), crate::transport::TransportError> {
        self.send_datagram(payload)
    }
}

impl DatagramReceiver for MasqueClient {
    async fn recv_datagram(&self) -> Result<Vec<u8>, crate::transport::TransportError> {
        self.recv_datagram().await
    }
}

impl DatagramSender for MasqueProxy {
    fn send_datagram(&self, payload: &[u8]) -> Result<(), crate::transport::TransportError> {
        self.send_datagram(payload)
    }
}

impl DatagramReceiver for MasqueProxy {
    async fn recv_datagram(&self) -> Result<Vec<u8>, crate::transport::TransportError> {
        self.recv_datagram().await
    }
}

impl<T: DatagramSender> DatagramSender for Arc<T> {
    fn send_datagram(&self, payload: &[u8]) -> Result<(), crate::transport::TransportError> {
        (**self).send_datagram(payload)
    }
}

impl<T: DatagramReceiver> DatagramReceiver for Arc<T> {
    async fn recv_datagram(&self) -> Result<Vec<u8>, crate::transport::TransportError> {
        (**self).recv_datagram().await
    }
}

/// Traffic byte counters for a tunnel session.
///
/// Uses atomic counters for lock-free updates from concurrent inbound/outbound loops.
pub struct TrafficStats {
    /// Bytes sent through the tunnel (TUN → network).
    pub bytes_sent: AtomicU64,
    /// Bytes received from the tunnel (network → TUN).
    pub bytes_received: AtomicU64,
}

impl TrafficStats {
    /// Create a new zero-initialized traffic stats counter.
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Bidirectional packet pipeline: TUN ↔ EncryptedChannel ↔ MASQUE.
///
/// Drives two concurrent loops for inbound (TUN → network) and outbound
/// (network → TUN) packet flow. Stops when the cancellation token fires
/// or an error occurs.
pub struct TunnelPipeline<T, S, R>
where
    T: TunDevice,
    S: DatagramSender,
    R: DatagramReceiver,
{
    tun: T,
    channel: Mutex<EncryptedChannel>,
    sender: S,
    receiver: R,
    stats: Arc<TrafficStats>,
}

impl<T, S, R> TunnelPipeline<T, S, R>
where
    T: TunDevice,
    S: DatagramSender,
    R: DatagramReceiver,
{
    /// Create a new tunnel pipeline.
    ///
    /// - `tun`: TUN device for reading/writing IP packets
    /// - `channel`: EncryptedChannel for encrypt/decrypt
    /// - `sender`: MASQUE sender for outbound datagrams
    /// - `receiver`: MASQUE receiver for inbound datagrams
    /// - `stats`: Shared traffic byte counters
    pub fn new(tun: T, channel: EncryptedChannel, sender: S, receiver: R, stats: Arc<TrafficStats>) -> Self {
        Self {
            tun,
            channel: Mutex::new(channel),
            sender,
            receiver,
            stats,
        }
    }

    /// Run the pipeline until the cancellation token is triggered.
    ///
    /// Drives both inbound and outbound loops concurrently.
    /// Returns the first error encountered, or `TunnelError::Cancelled` if
    /// the token was triggered.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), TunnelError> {
        tokio::select! {
            result = self.run_inbound(&cancel) => result,
            result = self.run_outbound(&cancel) => result,
            () = cancel.cancelled() => Err(TunnelError::Cancelled),
        }
    }

    /// Inbound loop: TUN recv → encrypt → MASQUE send.
    async fn run_inbound(&self, cancel: &CancellationToken) -> Result<(), TunnelError> {
        let mut buf = vec![0u8; TUN_READ_BUF_SIZE];
        loop {
            if cancel.is_cancelled() {
                return Err(TunnelError::Cancelled);
            }

            let n = self.tun.recv(&mut buf).await?;
            if n == 0 {
                continue;
            }

            let mtu = self.tun.mtu();
            if n > usize::from(mtu) {
                tracing::warn!(size = n, mtu = mtu, "dropping oversized packet");
                continue;
            }

            let encrypted = {
                let mut ch = self.channel.lock().expect("channel lock poisoned");
                ch.send(&buf[..n])?
            };

            if let Err(e) = self.sender.send_datagram(&encrypted) {
                if e.to_string().contains("too large") {
                    tracing::warn!(size = encrypted.len(), error = %e, "dropping packet: datagram too large for QUIC");
                    continue;
                }
                return Err(TunnelError::Transport(e));
            }
            self.stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    /// Outbound loop: MASQUE recv → decrypt → TUN send.
    async fn run_outbound(&self, cancel: &CancellationToken) -> Result<(), TunnelError> {
        loop {
            if cancel.is_cancelled() {
                return Err(TunnelError::Cancelled);
            }

            let encrypted = self.receiver.recv_datagram().await?;

            let plaintext = {
                let mut ch = self.channel.lock().expect("channel lock poisoned");
                ch.recv(&encrypted)?
            };

            self.tun.send(&plaintext).await?;
            self.stats.bytes_received.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::KEY_LEN;
    use crate::transport::encrypted_channel::EncryptedChannel;
    use crate::tunnel::mock_tun::MockTun;
    use crate::tunnel::tun_device::DEFAULT_TUNNEL_MTU;
    use std::sync::Arc;
    use tokio::sync::Mutex as TokioMutex;
    use tokio::sync::mpsc;

    const TEST_TX_KEY: [u8; KEY_LEN] = [0x01; KEY_LEN];
    const TEST_RX_KEY: [u8; KEY_LEN] = [0x02; KEY_LEN];

    // -- Mock datagram sender/receiver for pipeline testing --

    struct MockDatagramEndpoint {
        tx: mpsc::Sender<Vec<u8>>,
        rx: TokioMutex<mpsc::Receiver<Vec<u8>>>,
    }

    impl MockDatagramEndpoint {
        fn new_pair() -> (Self, Self) {
            let (tx_a, rx_b) = mpsc::channel(256);
            let (tx_b, rx_a) = mpsc::channel(256);
            let a = Self {
                tx: tx_a,
                rx: TokioMutex::new(rx_a),
            };
            let b = Self {
                tx: tx_b,
                rx: TokioMutex::new(rx_b),
            };
            (a, b)
        }
    }

    impl DatagramSender for Arc<MockDatagramEndpoint> {
        fn send_datagram(&self, payload: &[u8]) -> Result<(), crate::transport::TransportError> {
            self.tx
                .try_send(payload.to_vec())
                .map_err(|e| crate::transport::TransportError::MasqueDatagram(e.to_string()))
        }
    }

    impl DatagramReceiver for Arc<MockDatagramEndpoint> {
        async fn recv_datagram(&self) -> Result<Vec<u8>, crate::transport::TransportError> {
            let mut rx = self.rx.lock().await;
            rx.recv()
                .await
                .ok_or_else(|| crate::transport::TransportError::MasqueDatagram("channel closed".to_string()))
        }
    }

    type TestPipeline = TunnelPipeline<MockTun, Arc<MockDatagramEndpoint>, Arc<MockDatagramEndpoint>>;
    type TestHandle = super::super::mock_tun::MockTunHandle;

    /// Helper: create paired pipelines (client-side and proxy-side) connected
    /// by mock datagram channels.
    fn setup_paired_pipelines() -> (TestPipeline, TestHandle, TestPipeline, TestHandle) {
        let (client_tun, client_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let (proxy_tun, proxy_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);

        let (client_endpoint, proxy_endpoint) = MockDatagramEndpoint::new_pair();
        let client_endpoint = Arc::new(client_endpoint);
        let proxy_endpoint = Arc::new(proxy_endpoint);

        // Client encrypts with tx_key, proxy decrypts with rx_key (swapped)
        let client_channel = EncryptedChannel::new(TEST_TX_KEY, TEST_RX_KEY);
        let proxy_channel = EncryptedChannel::new(TEST_RX_KEY, TEST_TX_KEY);

        let client_pipeline = TunnelPipeline::new(
            client_tun,
            client_channel,
            Arc::clone(&client_endpoint),
            Arc::clone(&client_endpoint),
            Arc::new(TrafficStats::new()),
        );

        let proxy_pipeline = TunnelPipeline::new(
            proxy_tun,
            proxy_channel,
            Arc::clone(&proxy_endpoint),
            Arc::clone(&proxy_endpoint),
            Arc::new(TrafficStats::new()),
        );

        (client_pipeline, client_handle, proxy_pipeline, proxy_handle)
    }

    // T-4: Inbound pipeline: TUN → encrypt → datagram send
    #[tokio::test]
    async fn inbound_pipeline_tun_to_datagram() {
        let (client_tun, client_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let (endpoint_a, endpoint_b) = MockDatagramEndpoint::new_pair();
        let endpoint_a = Arc::new(endpoint_a);
        let endpoint_b = Arc::new(endpoint_b);

        let channel = EncryptedChannel::new(TEST_TX_KEY, TEST_RX_KEY);
        let pipeline = TunnelPipeline::new(
            client_tun,
            channel,
            Arc::clone(&endpoint_a),
            Arc::clone(&endpoint_a),
            Arc::new(TrafficStats::new()),
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let pipeline_handle = tokio::spawn(async move { pipeline.run(cancel_clone).await });

        // Inject a packet into the TUN
        let packet = b"hello-tunnel";
        client_handle.inject_packet(packet).await.expect("inject");

        // The encrypted packet should appear on endpoint_b's receiver
        let encrypted = {
            let mut rx = endpoint_b.rx.lock().await;
            tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .expect("timeout")
                .expect("recv")
        };

        // Verify we can decrypt it back
        let mut decrypt_channel = EncryptedChannel::new(TEST_RX_KEY, TEST_TX_KEY);
        let decrypted = decrypt_channel.recv(&encrypted).expect("decrypt");
        assert_eq!(decrypted, packet);

        cancel.cancel();
        let _ = pipeline_handle.await;
    }

    // T-5: Outbound pipeline: datagram recv → decrypt → TUN send
    #[tokio::test]
    async fn outbound_pipeline_datagram_to_tun() {
        let (client_tun, client_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let (endpoint_a, endpoint_b) = MockDatagramEndpoint::new_pair();
        let endpoint_a = Arc::new(endpoint_a);
        let endpoint_b = Arc::new(endpoint_b);

        let channel = EncryptedChannel::new(TEST_TX_KEY, TEST_RX_KEY);
        let pipeline = TunnelPipeline::new(
            client_tun,
            channel,
            Arc::clone(&endpoint_a),
            Arc::clone(&endpoint_a),
            Arc::new(TrafficStats::new()),
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let pipeline_handle = tokio::spawn(async move { pipeline.run(cancel_clone).await });

        // Encrypt a packet as if it came from the remote side
        let original = b"from-remote";
        let encrypted = {
            let mut encrypt_channel = EncryptedChannel::new(TEST_RX_KEY, TEST_TX_KEY);
            encrypt_channel.send(original).expect("encrypt")
        };

        // Send it into endpoint_b → will arrive at endpoint_a's receiver
        endpoint_b.tx.send(encrypted).await.expect("send");

        // The decrypted packet should appear on the TUN
        let captured = tokio::time::timeout(std::time::Duration::from_secs(2), client_handle.capture_packet())
            .await
            .expect("timeout")
            .expect("capture");

        assert_eq!(captured, original);

        cancel.cancel();
        let _ = pipeline_handle.await;
    }

    // T-6: Bidirectional pipeline echo
    #[tokio::test]
    async fn bidirectional_pipeline() {
        let (client_pipeline, client_handle, proxy_pipeline, proxy_handle) = setup_paired_pipelines();

        let cancel = CancellationToken::new();
        let cancel_c = cancel.clone();
        let cancel_p = cancel.clone();

        let client_task = tokio::spawn(async move { client_pipeline.run(cancel_c).await });
        let proxy_task = tokio::spawn(async move { proxy_pipeline.run(cancel_p).await });

        // Client → Proxy: inject packet into client TUN, capture from proxy TUN
        let packet = b"client-to-proxy";
        client_handle.inject_packet(packet).await.expect("inject");

        let captured = tokio::time::timeout(std::time::Duration::from_secs(2), proxy_handle.capture_packet())
            .await
            .expect("timeout")
            .expect("capture");
        assert_eq!(captured, packet);

        // Proxy → Client: inject packet into proxy TUN, capture from client TUN
        let reply = b"proxy-to-client";
        proxy_handle.inject_packet(reply).await.expect("inject");

        let captured = tokio::time::timeout(std::time::Duration::from_secs(2), client_handle.capture_packet())
            .await
            .expect("timeout")
            .expect("capture");
        assert_eq!(captured, reply);

        cancel.cancel();
        let _ = client_task.await;
        let _ = proxy_task.await;
    }

    // T-7: Oversized packet dropped
    #[tokio::test]
    async fn oversized_packet_dropped() {
        let mtu: u16 = 100;
        let (client_tun, client_handle) = MockTun::new(mtu);
        let (endpoint_a, endpoint_b) = MockDatagramEndpoint::new_pair();
        let endpoint_a = Arc::new(endpoint_a);
        let endpoint_b = Arc::new(endpoint_b);

        let channel = EncryptedChannel::new(TEST_TX_KEY, TEST_RX_KEY);
        let pipeline = TunnelPipeline::new(
            client_tun,
            channel,
            Arc::clone(&endpoint_a),
            Arc::clone(&endpoint_a),
            Arc::new(TrafficStats::new()),
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let pipeline_handle = tokio::spawn(async move { pipeline.run(cancel_clone).await });

        // Inject an oversized packet (larger than MTU)
        let oversized = vec![0xAA; usize::from(mtu) + 1];
        client_handle.inject_packet(&oversized).await.expect("inject oversized");

        // Then inject a valid packet
        let valid = b"small";
        client_handle.inject_packet(valid).await.expect("inject valid");

        // Only the valid packet should arrive (oversized was dropped)
        let received = {
            let mut rx = endpoint_b.rx.lock().await;
            tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .expect("timeout")
                .expect("recv")
        };

        // Decrypt and verify it's the small packet, not the oversized one
        let mut decrypt_channel = EncryptedChannel::new(TEST_RX_KEY, TEST_TX_KEY);
        let decrypted = decrypt_channel.recv(&received).expect("decrypt");
        assert_eq!(decrypted, valid);

        cancel.cancel();
        let _ = pipeline_handle.await;
    }

    // T-8: Pipeline cancellation stops both halves
    #[tokio::test]
    async fn pipeline_cancellation() {
        let (client_tun, _client_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let (endpoint_a, _endpoint_b) = MockDatagramEndpoint::new_pair();
        let endpoint_a = Arc::new(endpoint_a);

        let channel = EncryptedChannel::new(TEST_TX_KEY, TEST_RX_KEY);
        let pipeline = TunnelPipeline::new(
            client_tun,
            channel,
            Arc::clone(&endpoint_a),
            Arc::clone(&endpoint_a),
            Arc::new(TrafficStats::new()),
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let pipeline_handle = tokio::spawn(async move { pipeline.run(cancel_clone).await });

        // Give pipeline time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cancel
        cancel.cancel();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), pipeline_handle)
            .await
            .expect("pipeline should stop within timeout")
            .expect("task join");

        assert!(matches!(result, Err(TunnelError::Cancelled)));
    }

    // T-9: Multiple packets through pipeline in sequence
    #[tokio::test]
    async fn sequential_packets_through_pipeline() {
        let (client_pipeline, client_handle, proxy_pipeline, proxy_handle) = setup_paired_pipelines();

        let cancel = CancellationToken::new();
        let cancel_c = cancel.clone();
        let cancel_p = cancel.clone();

        let _client_task = tokio::spawn(async move { client_pipeline.run(cancel_c).await });
        let _proxy_task = tokio::spawn(async move { proxy_pipeline.run(cancel_p).await });

        let packet_count = 10usize;
        for i in 0..packet_count {
            let msg = format!("pkt-{i}");
            client_handle.inject_packet(msg.as_bytes()).await.expect("inject");

            let captured = tokio::time::timeout(std::time::Duration::from_secs(2), proxy_handle.capture_packet())
                .await
                .expect("timeout")
                .expect("capture");
            assert_eq!(captured, msg.as_bytes(), "mismatch at packet {i}");
        }

        cancel.cancel();
    }

    // T-10: Pipeline with 100 packets throughput
    #[tokio::test]
    async fn high_throughput_pipeline() {
        let (client_pipeline, client_handle, proxy_pipeline, proxy_handle) = setup_paired_pipelines();

        let cancel = CancellationToken::new();
        let cancel_c = cancel.clone();
        let cancel_p = cancel.clone();

        let _client_task = tokio::spawn(async move { client_pipeline.run(cancel_c).await });
        let _proxy_task = tokio::spawn(async move { proxy_pipeline.run(cancel_p).await });

        let packet_count = 100usize;
        for i in 0..packet_count {
            let msg = format!("throughput-{i:04}");
            client_handle.inject_packet(msg.as_bytes()).await.expect("inject");

            let captured = tokio::time::timeout(std::time::Duration::from_secs(2), proxy_handle.capture_packet())
                .await
                .expect("timeout")
                .expect("capture");
            assert_eq!(captured, msg.as_bytes(), "mismatch at packet {i}");
        }

        cancel.cancel();
    }

    // T-11: Traffic stats are counted correctly
    #[tokio::test]
    async fn traffic_stats_counted() {
        let (client_tun, client_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let (proxy_tun, proxy_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);

        let (client_endpoint, proxy_endpoint) = MockDatagramEndpoint::new_pair();
        let client_endpoint = Arc::new(client_endpoint);
        let proxy_endpoint = Arc::new(proxy_endpoint);

        let client_channel = EncryptedChannel::new(TEST_TX_KEY, TEST_RX_KEY);
        let proxy_channel = EncryptedChannel::new(TEST_RX_KEY, TEST_TX_KEY);

        let client_stats = Arc::new(TrafficStats::new());
        let proxy_stats = Arc::new(TrafficStats::new());

        let client_pipeline = TunnelPipeline::new(
            client_tun,
            client_channel,
            Arc::clone(&client_endpoint),
            Arc::clone(&client_endpoint),
            Arc::clone(&client_stats),
        );

        let proxy_pipeline = TunnelPipeline::new(
            proxy_tun,
            proxy_channel,
            Arc::clone(&proxy_endpoint),
            Arc::clone(&proxy_endpoint),
            Arc::clone(&proxy_stats),
        );

        let cancel = CancellationToken::new();
        let cancel_c = cancel.clone();
        let cancel_p = cancel.clone();

        let _client_task = tokio::spawn(async move { client_pipeline.run(cancel_c).await });
        let _proxy_task = tokio::spawn(async move { proxy_pipeline.run(cancel_p).await });

        // Client → Proxy: 3 packets
        let packet_sizes: [usize; 3] = [10, 20, 30];
        let mut total_sent: u64 = 0;
        for size in &packet_sizes {
            let data = vec![0xAA; *size];
            client_handle.inject_packet(&data).await.expect("inject");
            total_sent += *size as u64;

            let _captured = tokio::time::timeout(std::time::Duration::from_secs(2), proxy_handle.capture_packet())
                .await
                .expect("timeout")
                .expect("capture");
        }

        // Proxy → Client: 2 packets
        let reply_sizes: [usize; 2] = [15, 25];
        let mut total_reply: u64 = 0;
        for size in &reply_sizes {
            let data = vec![0xBB; *size];
            proxy_handle.inject_packet(&data).await.expect("inject");
            total_reply += *size as u64;

            let _captured = tokio::time::timeout(std::time::Duration::from_secs(2), client_handle.capture_packet())
                .await
                .expect("timeout")
                .expect("capture");
        }

        // Verify client stats: sent = packets from TUN, received = packets to TUN
        assert_eq!(client_stats.bytes_sent.load(Ordering::Relaxed), total_sent);
        assert_eq!(client_stats.bytes_received.load(Ordering::Relaxed), total_reply);

        // Verify proxy stats: sent = reply packets, received = client packets
        assert_eq!(proxy_stats.bytes_sent.load(Ordering::Relaxed), total_reply);
        assert_eq!(proxy_stats.bytes_received.load(Ordering::Relaxed), total_sent);

        cancel.cancel();
    }

    // -- AC-7 (pipeline bridge): Full pipeline with HarpSender/HarpReceiver --
    // FRD: specs/frds/FRD-20260223-harp-pipeline-bridge.md

    #[tokio::test]
    async fn harp_pipeline_bidirectional() {
        use crate::transport::harp::{HarpReceiver, HarpSender};

        // Channels: client_tx → proxy_rx (client sends to proxy)
        //           proxy_tx → client_rx (proxy sends to client)
        let (client_tx, proxy_rx) = mpsc::channel::<Vec<u8>>(256);
        let (proxy_tx, client_rx) = mpsc::channel::<Vec<u8>>(256);

        let (client_tun, client_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let (proxy_tun, proxy_handle) = MockTun::new(DEFAULT_TUNNEL_MTU);

        let client_channel = EncryptedChannel::new(TEST_TX_KEY, TEST_RX_KEY);
        let proxy_channel = EncryptedChannel::new(TEST_RX_KEY, TEST_TX_KEY);

        let client_sender = HarpSender::new(client_tx);
        let client_receiver = HarpReceiver::new(Arc::new(TokioMutex::new(client_rx)));
        let proxy_sender = HarpSender::new(proxy_tx);
        let proxy_receiver = HarpReceiver::new(Arc::new(TokioMutex::new(proxy_rx)));

        let client_pipeline = TunnelPipeline::new(
            client_tun,
            client_channel,
            client_sender,
            client_receiver,
            Arc::new(TrafficStats::new()),
        );

        let proxy_pipeline = TunnelPipeline::new(
            proxy_tun,
            proxy_channel,
            proxy_sender,
            proxy_receiver,
            Arc::new(TrafficStats::new()),
        );

        let cancel = CancellationToken::new();
        let cancel_c = cancel.clone();
        let cancel_p = cancel.clone();

        let _client_task = tokio::spawn(async move { client_pipeline.run(cancel_c).await });
        let _proxy_task = tokio::spawn(async move { proxy_pipeline.run(cancel_p).await });

        // Client → Proxy
        let msg = b"harp-client-to-proxy";
        client_handle.inject_packet(msg).await.expect("inject");
        let captured = tokio::time::timeout(std::time::Duration::from_secs(2), proxy_handle.capture_packet())
            .await
            .expect("timeout")
            .expect("capture");
        assert_eq!(captured, msg);

        // Proxy → Client
        let reply = b"harp-proxy-to-client";
        proxy_handle.inject_packet(reply).await.expect("inject");
        let captured = tokio::time::timeout(std::time::Duration::from_secs(2), client_handle.capture_packet())
            .await
            .expect("timeout")
            .expect("capture");
        assert_eq!(captured, reply);

        cancel.cancel();
    }
}
