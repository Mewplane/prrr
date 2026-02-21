// FRD: specs/frds/FRD-008.md

//! Mock TUN device for testing without root privileges.
//!
//! [`MockTun`] implements [`TunDevice`] using tokio channels, enabling
//! deterministic packet injection and capture in tests.

use tokio::sync::Mutex;
use tokio::sync::mpsc;

use super::tun_device::TunDevice;

/// Default channel capacity for mock TUN packet buffers.
const MOCK_CHANNEL_CAPACITY: usize = 256;

/// Default mock device name.
const MOCK_TUN_NAME: &str = "mock0";

/// Mock TUN device backed by tokio channels.
///
/// Packets "received" by the VPN come from the inject channel.
/// Packets "sent" by the VPN are captured in the capture channel.
pub struct MockTun {
    name: String,
    mtu: u16,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    tx: mpsc::Sender<Vec<u8>>,
}

/// Test handle for injecting packets into and capturing packets from a [`MockTun`].
pub struct MockTunHandle {
    /// Send packets into the mock TUN (simulates packets arriving at the interface).
    inject_tx: mpsc::Sender<Vec<u8>>,
    /// Receive packets that the VPN wrote to the mock TUN.
    capture_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl MockTun {
    /// Create a new mock TUN device and its test handle.
    ///
    /// The returned `MockTunHandle` is used in tests to inject and capture packets.
    pub fn new(mtu: u16) -> (Self, MockTunHandle) {
        let (inject_tx, rx) = mpsc::channel(MOCK_CHANNEL_CAPACITY);
        let (tx, capture_rx) = mpsc::channel(MOCK_CHANNEL_CAPACITY);

        let tun = Self {
            name: MOCK_TUN_NAME.to_string(),
            mtu,
            rx: Mutex::new(rx),
            tx,
        };

        let handle = MockTunHandle {
            inject_tx,
            capture_rx: Mutex::new(capture_rx),
        };

        (tun, handle)
    }
}

impl TunDevice for MockTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(packet) => {
                let len = packet.len().min(buf.len());
                buf[..len].copy_from_slice(&packet[..len]);
                Ok(len)
            }
            None => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "mock TUN closed")),
        }
    }

    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "mock TUN closed"))?;
        Ok(buf.len())
    }
}

/// Factory for creating [`MockTun`] devices in multi-client tests.
///
/// Each call to `create_tun()` returns a fresh `(MockTun, MockTunHandle)` pair.
/// The MTU is fixed at construction time.
pub struct MockTunFactory {
    mtu: u16,
}

impl MockTunFactory {
    /// Create a new factory that produces MockTun devices with the given MTU.
    pub fn new(mtu: u16) -> Self {
        Self { mtu }
    }
}

impl super::TunFactory for MockTunFactory {
    type Tun = MockTun;
    type Handle = MockTunHandle;

    fn create_tun(&self, _config: &super::tun_device::TunConfig) -> Result<(MockTun, MockTunHandle), super::TunnelError> {
        Ok(MockTun::new(self.mtu))
    }
}

impl MockTunHandle {
    /// Inject a packet into the mock TUN device (simulates an incoming IP packet).
    pub async fn inject_packet(&self, packet: &[u8]) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.inject_tx.send(packet.to_vec()).await
    }

    /// Capture a packet that the VPN wrote to the mock TUN device.
    ///
    /// Returns `None` if the channel is closed.
    pub async fn capture_packet(&self) -> Option<Vec<u8>> {
        let mut rx = self.capture_rx.lock().await;
        rx.recv().await
    }
}

/// Factory that stores server-side [`MockTunHandle`]s for E2E data testing.
///
/// When the server calls `create_tun()`, the returned TUN goes to the pipeline
/// while the real handle is stored internally. The caller (server) receives a
/// dummy handle that it discards anyway. Tests retrieve the real handles via
/// [`take_handles`](CapturingMockTunFactory::take_handles) to inject/capture
/// packets on the server side of the tunnel.
pub struct CapturingMockTunFactory {
    mtu: u16,
    handles: std::sync::Mutex<Vec<MockTunHandle>>,
}

impl CapturingMockTunFactory {
    /// Create a new capturing factory with the given MTU.
    pub fn new(mtu: u16) -> Self {
        Self {
            mtu,
            handles: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Take all stored handles, draining the internal list.
    pub fn take_handles(&self) -> Vec<MockTunHandle> {
        self.handles.lock().expect("lock").drain(..).collect()
    }
}

impl super::TunFactory for CapturingMockTunFactory {
    type Tun = MockTun;
    type Handle = MockTunHandle;

    fn create_tun(&self, _config: &super::tun_device::TunConfig) -> Result<(MockTun, MockTunHandle), super::TunnelError> {
        // Create the real pair — TUN goes to the server pipeline.
        let (tun, real_handle) = MockTun::new(self.mtu);
        // Store the real handle so tests can inject/capture packets.
        self.handles.lock().expect("lock").push(real_handle);
        // Create a dummy handle for the server (it discards it with `_handle`).
        let (_dummy_tun, dummy_handle) = MockTun::new(self.mtu);
        Ok((tun, dummy_handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::tun_device::DEFAULT_TUNNEL_MTU;

    // T-1: MockTun inject and capture round-trip
    #[tokio::test]
    async fn mock_tun_inject_and_capture() {
        let (tun, handle) = MockTun::new(DEFAULT_TUNNEL_MTU);

        // Inject a packet → recv from TUN
        let injected = b"test-ip-packet";
        handle.inject_packet(injected).await.expect("inject");

        let mut buf = vec![0u8; 1500];
        let n = tun.recv(&mut buf).await.expect("recv");
        assert_eq!(&buf[..n], injected);

        // Send a packet → capture from handle
        let sent = b"outgoing-packet";
        let written = tun.send(sent).await.expect("send");
        assert_eq!(written, sent.len());

        let captured = handle.capture_packet().await.expect("capture");
        assert_eq!(captured, sent);
    }

    // T-2: MockTun respects name and MTU accessors
    #[tokio::test]
    async fn mock_tun_name_and_mtu() {
        let (tun, _handle) = MockTun::new(1400);

        assert_eq!(tun.name(), MOCK_TUN_NAME);
        assert_eq!(tun.mtu(), 1400);
    }

    #[tokio::test]
    async fn mock_tun_closed_recv_returns_error() {
        let (tun, handle) = MockTun::new(DEFAULT_TUNNEL_MTU);

        // Drop the inject side to close the channel
        drop(handle);

        let mut buf = vec![0u8; 1500];
        let result = tun.recv(&mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_tun_multiple_packets() {
        let (tun, handle) = MockTun::new(DEFAULT_TUNNEL_MTU);
        let packet_count = 10usize;

        for i in 0..packet_count {
            let packet = format!("packet-{i}");
            handle.inject_packet(packet.as_bytes()).await.expect("inject");
        }

        for i in 0..packet_count {
            let mut buf = vec![0u8; 1500];
            let n = tun.recv(&mut buf).await.expect("recv");
            let expected = format!("packet-{i}");
            assert_eq!(&buf[..n], expected.as_bytes());
        }
    }
}
