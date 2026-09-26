// FRD: specs/frds/FRD-20260223-client-reconnection.md

//! Transport-agnostic client reconnection with exponential backoff.
//!
//! When a VPN transport connection drops, the client re-establishes a
//! new session (new handshake, new keys) automatically. The TUN device
//! persists across reconnections so the client's IP address does not
//! change.
//!
//! The reconnection loop calls [`ClientTransport::connect()`] in a retry
//! loop with exponential backoff and jitter. On cancellation the loop
//! exits cleanly.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::{
    handshake::noise_ik::KeyPair,
    transport::{ClientTransport, encrypted_channel::EncryptedChannel, traits::ClientConnectParams},
    tunnel::{TunnelError, pipeline::TrafficStats, tun_device::TunDevice},
};

/// Default initial backoff delay in milliseconds.
pub const DEFAULT_BACKOFF_INITIAL_MS: u64 = 1000;

/// Default maximum backoff delay in milliseconds.
pub const DEFAULT_BACKOFF_MAX_MS: u64 = 30_000;

/// Jitter fraction applied to backoff delays (+-25%).
const JITTER_FRACTION_PERCENT: u64 = 25;

/// Percentage base for jitter calculation.
const PERCENT_BASE: u64 = 100;

/// Exponential backoff state with jitter.
///
/// Starts at `initial_ms`, doubles on each consecutive failure, and
/// caps at `max_ms`. Each delay has +-25% jitter applied.
pub struct BackoffState {
    initial_ms: u64,
    max_ms: u64,
    current_ms: u64,
}

impl BackoffState {
    /// Create a new backoff state with the given initial and maximum delays.
    pub fn new(initial_ms: u64, max_ms: u64) -> Self {
        Self {
            initial_ms,
            max_ms,
            current_ms: initial_ms,
        }
    }

    /// Return the next backoff delay (without jitter) and advance the state.
    ///
    /// The delay doubles on each call, capped at `max_ms`.
    pub fn next_delay_ms(&mut self) -> u64 {
        let delay = self.current_ms;
        self.current_ms = self.current_ms.saturating_mul(2).min(self.max_ms);
        delay
    }

    /// Return the next backoff delay with +-25% jitter applied.
    pub fn next_delay_with_jitter(&mut self) -> Duration {
        let base_ms = self.next_delay_ms();
        let jitter_range = base_ms * JITTER_FRACTION_PERCENT / PERCENT_BASE;
        let jittered = if jitter_range > 0 {
            let offset = crate::obfuscation::traffic_morph::compute_jitter(jitter_range * 2);
            let offset_ms = offset.as_millis() as u64;
            // Shift from [0, 2*range) to [-range, +range)
            base_ms.saturating_add(offset_ms).saturating_sub(jitter_range)
        } else {
            base_ms
        };
        Duration::from_millis(jittered)
    }

    /// Reset the backoff state to the initial delay.
    pub fn reset(&mut self) {
        self.current_ms = self.initial_ms;
    }
}

/// Parameters for the reconnection loop.
pub struct ReconnectConfig {
    /// Initial backoff delay in milliseconds.
    pub backoff_initial_ms: u64,
    /// Maximum backoff delay in milliseconds.
    pub backoff_max_ms: u64,
}

/// Cryptographic material needed for each reconnection handshake.
pub struct ReconnectCryptoParams<'a> {
    /// Client's Noise IK keypair.
    pub noise_keypair: &'a KeyPair,
    /// Server's Noise IK public key.
    pub server_noise_pub: &'a [u8; 32],
    /// Server's ML-KEM-768 encapsulation key.
    pub server_kem_pub: &'a [u8],
}

/// Run the VPN client with automatic reconnection on transport failure.
///
/// Creates a new session (new handshake, new keys) on each reconnection
/// attempt. The TUN device persists across reconnections.
///
/// When `route_manager` is provided, routes are set up after each successful
/// transport connection and torn down before retrying or exiting. This
/// ensures routing only exists while the tunnel is active.
///
/// When `registrar` is provided, prrr publishes its ecosystem descriptor
/// (SPEC §3) on tunnel up and updates it to the not-connected state on tunnel
/// down. Registration is best-effort and never blocks the tunnel.
///
/// Exits cleanly when `cancel` is triggered (returns `Ok(())`).
/// Only retries on transport/pipeline errors, not on cancellation.
pub async fn run_with_reconnect<T: TunDevice + Clone>(
    transport: &dyn ClientTransport,
    crypto: &ReconnectCryptoParams<'_>,
    tun: T,
    config: &ReconnectConfig,
    mut route_manager: Option<&mut crate::routing::RouteManager>,
    registrar: Option<&crate::ecosystem::EcosystemRegistrar>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let mut backoff = BackoffState::new(config.backoff_initial_ms, config.backoff_max_ms);

    loop {
        let params = ClientConnectParams {
            noise_keypair: crypto.noise_keypair,
            server_noise_pub: crypto.server_noise_pub,
            server_kem_pub: crypto.server_kem_pub,
            cancel: cancel.clone(),
        };

        let conn = match transport.connect(params).await {
            Ok(conn) => {
                backoff.reset();
                tracing::info!(transport = transport.name(), "transport connected");
                conn
            }
            Err(e) => {
                if cancel.is_cancelled() {
                    tracing::info!("reconnect loop cancelled during connect");
                    return Ok(());
                }
                let delay = backoff.next_delay_with_jitter();
                tracing::warn!(
                    transport = transport.name(),
                    error = %e,
                    backoff_ms = delay.as_millis() as u64,
                    "transport connect failed, retrying"
                );
                tokio::select! {
                    () = tokio::time::sleep(delay) => continue,
                    () = cancel.cancelled() => {
                        tracing::info!("reconnect loop cancelled during backoff");
                        return Ok(());
                    }
                }
            }
        };

        // Set up routes after transport connects
        if let Some(ref mut rm) = route_manager {
            rm.up();
        }
        // Register with the ecosystem registry on tunnel up (best-effort).
        if let Some(reg) = registrar {
            reg.on_up();
        }

        let channel = EncryptedChannel::new(conn.session_keys.tx_key, conn.session_keys.rx_key);
        let stats = std::sync::Arc::new(TrafficStats::new());
        let pipeline = crate::tunnel::TunnelPipeline::new(tun.clone(), channel, conn.sender, conn.receiver, stats);

        tracing::info!("tunnel pipeline running");
        match pipeline.run(cancel.clone()).await {
            Ok(()) => {
                // Tear down routes on clean exit
                if let Some(ref mut rm) = route_manager {
                    rm.down();
                }
                if let Some(reg) = registrar {
                    reg.on_down();
                }
                tracing::info!("tunnel pipeline exited cleanly");
                return Ok(());
            }
            Err(TunnelError::Cancelled) => {
                // Tear down routes on cancellation
                if let Some(ref mut rm) = route_manager {
                    rm.down();
                }
                if let Some(reg) = registrar {
                    reg.on_down();
                }
                tracing::info!("tunnel pipeline cancelled — shutting down");
                return Ok(());
            }
            Err(e) => {
                // Tear down routes before retry
                if let Some(ref mut rm) = route_manager {
                    rm.down();
                }
                if let Some(reg) = registrar {
                    reg.on_down();
                }
                if cancel.is_cancelled() {
                    tracing::info!("reconnect loop cancelled after pipeline error");
                    return Ok(());
                }
                let delay = backoff.next_delay_with_jitter();
                tracing::warn!(
                    transport = transport.name(),
                    error = %e,
                    backoff_ms = delay.as_millis() as u64,
                    "pipeline error, reconnecting"
                );
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    () = cancel.cancelled() => {
                        tracing::info!("reconnect loop cancelled during backoff");
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-20260223-client-reconnection.md

    use super::*;

    // -- AC-1: BackoffState::next_delay_ms() returns initial_ms on first call --

    #[test]
    fn backoff_initial_delay() {
        let mut backoff = BackoffState::new(DEFAULT_BACKOFF_INITIAL_MS, DEFAULT_BACKOFF_MAX_MS);
        assert_eq!(backoff.next_delay_ms(), DEFAULT_BACKOFF_INITIAL_MS);
    }

    // -- AC-2: BackoffState::next_delay_ms() doubles on consecutive calls --

    #[test]
    fn backoff_doubles_on_consecutive() {
        let mut backoff = BackoffState::new(DEFAULT_BACKOFF_INITIAL_MS, DEFAULT_BACKOFF_MAX_MS);
        let first = backoff.next_delay_ms();
        let second = backoff.next_delay_ms();
        let third = backoff.next_delay_ms();
        assert_eq!(first, DEFAULT_BACKOFF_INITIAL_MS);
        assert_eq!(second, DEFAULT_BACKOFF_INITIAL_MS * 2);
        assert_eq!(third, DEFAULT_BACKOFF_INITIAL_MS * 4);
    }

    // -- AC-3: BackoffState::next_delay_ms() caps at max_ms --

    #[test]
    fn backoff_caps_at_max() {
        let initial_ms: u64 = 1000;
        let max_ms: u64 = 5000;
        let mut backoff = BackoffState::new(initial_ms, max_ms);
        let _ = backoff.next_delay_ms(); // 1000
        let _ = backoff.next_delay_ms(); // 2000
        let _ = backoff.next_delay_ms(); // 4000
        let fourth = backoff.next_delay_ms(); // capped at 5000
        assert_eq!(fourth, max_ms);
        let fifth = backoff.next_delay_ms(); // still 5000
        assert_eq!(fifth, max_ms);
    }

    // -- AC-4: BackoffState::reset() returns to initial_ms --

    #[test]
    fn backoff_reset() {
        let mut backoff = BackoffState::new(DEFAULT_BACKOFF_INITIAL_MS, DEFAULT_BACKOFF_MAX_MS);
        let _ = backoff.next_delay_ms(); // 1000
        let _ = backoff.next_delay_ms(); // 2000
        backoff.reset();
        assert_eq!(backoff.next_delay_ms(), DEFAULT_BACKOFF_INITIAL_MS);
    }

    // -- AC-5: Jitter applied to backoff delay (within +-25%) --

    #[test]
    fn backoff_jitter_within_bounds() {
        let initial_ms: u64 = 1000;
        let max_ms: u64 = 30_000;
        let jitter_range = initial_ms * JITTER_FRACTION_PERCENT / PERCENT_BASE; // 250
        let lower_bound = initial_ms - jitter_range;
        let upper_bound = initial_ms + jitter_range;
        let sample_count: usize = 100;

        for _ in 0..sample_count {
            let mut backoff = BackoffState::new(initial_ms, max_ms);
            let delay = backoff.next_delay_with_jitter();
            let ms = delay.as_millis() as u64;
            assert!(
                ms >= lower_bound && ms <= upper_bound,
                "jittered delay {ms}ms outside [{lower_bound}, {upper_bound}]"
            );
        }
    }

    // -- AC-9: TunDevice for Arc<T> --

    #[tokio::test]
    async fn tun_device_arc_wrapper() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let (tun, handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = std::sync::Arc::new(tun);
        let tun_clone = std::sync::Arc::clone(&tun);

        // Both clones should reference the same device
        assert_eq!(tun.name(), tun_clone.name());
        assert_eq!(tun.mtu(), tun_clone.mtu());

        // Inject through handle, receive through Arc-wrapped TUN clone
        let test_packet = b"reconnect-tun-test";
        handle.inject_packet(test_packet).await.expect("inject");

        let mut buf = vec![0u8; 1500];
        let n = tun_clone.recv(&mut buf).await.expect("recv");
        assert_eq!(&buf[..n], test_packet);
    }

    // -- AC-6: run_with_reconnect retries on transport error --
    // -- AC-7: run_with_reconnect exits cleanly on cancellation --
    // -- AC-8: run_with_reconnect resets backoff after successful connect --

    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    use crate::{
        handshake::hybrid::SessionKeys,
        transport::{TransportError, traits::TransportConnection},
    };

    /// Mock transport that fails N times then succeeds once (pipeline immediately errors).
    struct FailNTransport {
        fail_count: AtomicU32,
        fail_target: u32,
        connect_count: Arc<AtomicU32>,
    }

    impl FailNTransport {
        fn new(fail_target: u32, connect_count: Arc<AtomicU32>) -> Self {
            Self {
                fail_count: AtomicU32::new(0),
                fail_target,
                connect_count,
            }
        }
    }

    impl ClientTransport for FailNTransport {
        fn name(&self) -> &str {
            "mock-fail-n"
        }

        fn connect<'a>(
            &'a self,
            _params: ClientConnectParams<'a>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<TransportConnection>> + Send + 'a>> {
            Box::pin(async {
                self.connect_count.fetch_add(1, Ordering::Relaxed);
                let count = self.fail_count.fetch_add(1, Ordering::Relaxed);
                if count < self.fail_target {
                    Err(anyhow::anyhow!("mock transport error #{}", count + 1))
                } else {
                    // Return a connection whose receiver immediately errors
                    // (simulates a very short-lived connection that triggers reconnect
                    // or the test cancels before pipeline runs)
                    Ok(mock_transport_connection())
                }
            })
        }
    }

    /// Mock transport that always succeeds but whose pipeline errors.
    struct PipelineErrorTransport {
        connect_count: Arc<AtomicU32>,
    }

    impl ClientTransport for PipelineErrorTransport {
        fn name(&self) -> &str {
            "mock-pipe-error"
        }

        fn connect<'a>(
            &'a self,
            _params: ClientConnectParams<'a>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<TransportConnection>> + Send + 'a>> {
            Box::pin(async {
                self.connect_count.fetch_add(1, Ordering::Relaxed);
                Ok(mock_transport_connection_that_errors())
            })
        }
    }

    /// Create a mock TransportConnection where receiver immediately returns an error.
    fn mock_transport_connection_that_errors() -> TransportConnection {
        use crate::{
            crypto::aead::KEY_LEN,
            transport::traits::{BoxedDatagramReceiver, BoxedDatagramSender},
        };

        struct ErrorSender;
        impl BoxedDatagramSender for ErrorSender {
            fn send_datagram(&self, _payload: &[u8]) -> Result<(), TransportError> {
                Err(TransportError::HarpChannelClosed)
            }
        }

        struct ErrorReceiver;
        impl BoxedDatagramReceiver for ErrorReceiver {
            fn recv_datagram(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>> {
                Box::pin(async { Err(TransportError::HarpChannelClosed) })
            }
        }

        TransportConnection {
            sender: Box::new(ErrorSender),
            receiver: Box::new(ErrorReceiver),
            session_keys: SessionKeys {
                tx_key: [0x01; KEY_LEN],
                rx_key: [0x02; KEY_LEN],
                header_key: [0x03; KEY_LEN],
            },
        }
    }

    /// Create a mock TransportConnection that blocks forever on recv.
    fn mock_transport_connection() -> TransportConnection {
        use crate::{
            crypto::aead::KEY_LEN,
            transport::traits::{BoxedDatagramReceiver, BoxedDatagramSender},
        };

        struct NoopSender;
        impl BoxedDatagramSender for NoopSender {
            fn send_datagram(&self, _payload: &[u8]) -> Result<(), TransportError> {
                Ok(())
            }
        }

        struct BlockingReceiver;
        impl BoxedDatagramReceiver for BlockingReceiver {
            fn recv_datagram(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>> {
                Box::pin(async {
                    // Block forever — test will cancel
                    std::future::pending().await
                })
            }
        }

        TransportConnection {
            sender: Box::new(NoopSender),
            receiver: Box::new(BlockingReceiver),
            session_keys: SessionKeys {
                tx_key: [0x01; KEY_LEN],
                rx_key: [0x02; KEY_LEN],
                header_key: [0x03; KEY_LEN],
            },
        }
    }

    struct TestCryptoMaterial {
        noise_keypair: KeyPair,
        server_noise_pub: [u8; 32],
        server_kem_pub: Vec<u8>,
    }

    impl TestCryptoMaterial {
        fn new() -> Self {
            Self {
                noise_keypair: KeyPair::generate().expect("keygen"),
                server_noise_pub: [0xAA; 32],
                server_kem_pub: vec![0xBB; 64],
            }
        }

        fn as_params(&self) -> ReconnectCryptoParams<'_> {
            ReconnectCryptoParams {
                noise_keypair: &self.noise_keypair,
                server_noise_pub: &self.server_noise_pub,
                server_kem_pub: &self.server_kem_pub,
            }
        }
    }

    #[tokio::test]
    async fn reconnect_retries_on_connect_error() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let connect_count = Arc::new(AtomicU32::new(0));
        let transport = FailNTransport::new(2, Arc::clone(&connect_count));

        let crypto = TestCryptoMaterial::new();
        let (tun, _handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1, // 1ms for fast test
            backoff_max_ms: 10,
        };

        // Cancel after transport succeeds and pipeline blocks
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            // Wait for 3 connect attempts (2 fail + 1 success)
            loop {
                if connect_count.load(Ordering::Relaxed) >= 3 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            cancel_clone.cancel();
        });

        let result = run_with_reconnect(&transport, &crypto.as_params(), tun, &config, None, None, cancel).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn reconnect_exits_on_cancel() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let connect_count = Arc::new(AtomicU32::new(0));
        let transport = FailNTransport::new(0, Arc::clone(&connect_count));

        let crypto = TestCryptoMaterial::new();
        let (tun, _handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1,
            backoff_max_ms: 10,
        };

        // Cancel immediately after first connect
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            loop {
                if connect_count.load(Ordering::Relaxed) >= 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            cancel_clone.cancel();
        });

        let result = run_with_reconnect(&transport, &crypto.as_params(), tun, &config, None, None, cancel).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn reconnect_retries_on_pipeline_error() {
        use crate::tunnel::{mock_tun::MockTun, tun_device::DEFAULT_TUNNEL_MTU};

        let connect_count = Arc::new(AtomicU32::new(0));
        let transport = PipelineErrorTransport {
            connect_count: Arc::clone(&connect_count),
        };

        let crypto = TestCryptoMaterial::new();
        let (tun, _handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let tun = Arc::new(tun);
        let cancel = CancellationToken::new();

        let config = ReconnectConfig {
            backoff_initial_ms: 1,
            backoff_max_ms: 10,
        };

        // Cancel after a few reconnect attempts
        let cancel_clone = cancel.clone();
        let count_clone = Arc::clone(&connect_count);
        let min_connect_attempts: u32 = 3;
        tokio::spawn(async move {
            loop {
                if count_clone.load(Ordering::Relaxed) >= min_connect_attempts {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            cancel_clone.cancel();
        });

        let result = run_with_reconnect(&transport, &crypto.as_params(), tun, &config, None, None, cancel).await;

        assert!(result.is_ok());
        assert!(connect_count.load(Ordering::Relaxed) >= min_connect_attempts);
    }
}
