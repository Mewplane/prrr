// FRD: specs/frds/FRD-DPI008.md, specs/frds/FRD-DPI009.md

//! PSK UDP obfuscation: ChaCha20 stream cipher wrapper for QUIC packets.
//!
//! Wraps raw UDP payloads in a ChaCha20 stream cipher layer keyed by a
//! per-client Pre-Shared Key (PSK). Each packet is prepended with a random
//! 8-byte nonce, making the wire format indistinguishable from random noise.
//!
//! # Wire Format
//!
//! ```text
//! [Nonce (8 bytes, random)] [Obfuscated Payload (N bytes)]
//! ```
//!
//! Since QUIC already provides authenticated encryption via TLS 1.3, the
//! outer obfuscation layer only needs confidentiality — no AEAD tag is
//! required. This keeps per-packet overhead to exactly 8 bytes.
//!
//! # Usage
//!
//! ```rust
//! use prrr::obfuscation::psk_udp::PskObfuscator;
//!
//! let key = [0x42u8; 32];
//! let obfuscator = PskObfuscator::new(key);
//!
//! let plaintext = b"QUIC packet data";
//! let packet = obfuscator.obfuscate(plaintext);
//! let recovered = obfuscator.deobfuscate(&packet).unwrap();
//! assert_eq!(recovered, plaintext);
//! ```

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::RngCore;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the random nonce prepended to each obfuscated packet (bytes).
const NONCE_LEN: usize = 8;

/// ChaCha20 requires a 12-byte nonce; we zero-pad our 8-byte random nonce.
const CHACHA20_NONCE_LEN: usize = 12;

/// Minimum valid obfuscated packet size: nonce + at least 1 byte of payload.
const MIN_PACKET_LEN: usize = NONCE_LEN + 1;

/// PSK key length in bytes (256 bits).
const PSK_KEY_LEN: usize = 32;

/// Per-packet overhead added by PSK obfuscation (nonce bytes).
///
/// When obfuscation is active, each UDP datagram grows by this many bytes.
/// Callers should reduce the effective MTU budget accordingly.
pub const PSK_NONCE_OVERHEAD: usize = NONCE_LEN;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from PSK obfuscation operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PskError {
    /// Packet is too short to contain a valid nonce + payload.
    #[error("packet too short: {len} bytes (minimum {MIN_PACKET_LEN})")]
    PacketTooShort {
        /// Actual packet length.
        len: usize,
    },
}

// ---------------------------------------------------------------------------
// PskObfuscator
// ---------------------------------------------------------------------------

/// ChaCha20-based UDP packet obfuscator keyed by a 256-bit PSK.
///
/// Each call to [`obfuscate`](Self::obfuscate) generates a fresh random
/// 8-byte nonce, applies ChaCha20, and prepends the nonce to the ciphertext.
/// [`deobfuscate`](Self::deobfuscate) reverses the process.
#[derive(Clone)]
pub struct PskObfuscator {
    /// 256-bit pre-shared key.
    key: [u8; PSK_KEY_LEN],
}

impl PskObfuscator {
    /// Create a new obfuscator from a 256-bit (32-byte) PSK.
    pub fn new(key: [u8; PSK_KEY_LEN]) -> Self {
        Self { key }
    }

    /// Obfuscate a plaintext payload.
    ///
    /// Generates a random 8-byte nonce, encrypts the payload with ChaCha20,
    /// and returns `[nonce (8B)] || [ciphertext (N B)]`.
    pub fn obfuscate(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        self.obfuscate_with_nonce(&nonce_bytes, plaintext)
    }

    /// Deobfuscate a packet back to the original plaintext.
    ///
    /// Splits the first 8 bytes as the nonce, then applies ChaCha20
    /// decryption (symmetric — same as encryption for a stream cipher).
    ///
    /// # Errors
    ///
    /// Returns [`PskError::PacketTooShort`] if the packet is shorter than
    /// 9 bytes (8-byte nonce + at least 1 byte of payload).
    pub fn deobfuscate(&self, packet: &[u8]) -> Result<Vec<u8>, PskError> {
        if packet.len() < MIN_PACKET_LEN {
            return Err(PskError::PacketTooShort { len: packet.len() });
        }

        let (nonce_bytes, ciphertext) = packet.split_at(NONCE_LEN);

        let mut chacha20_nonce = [0u8; CHACHA20_NONCE_LEN];
        chacha20_nonce[..NONCE_LEN].copy_from_slice(nonce_bytes);

        let mut output = ciphertext.to_vec();
        let mut cipher = ChaCha20::new((&self.key).into(), (&chacha20_nonce).into());
        cipher.apply_keystream(&mut output);

        Ok(output)
    }

    /// Obfuscate with a specific nonce (for deterministic testing).
    fn obfuscate_with_nonce(&self, nonce_bytes: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
        let mut chacha20_nonce = [0u8; CHACHA20_NONCE_LEN];
        chacha20_nonce[..NONCE_LEN].copy_from_slice(nonce_bytes);

        let mut ciphertext = plaintext.to_vec();
        let mut cipher = ChaCha20::new((&self.key).into(), (&chacha20_nonce).into());
        cipher.apply_keystream(&mut ciphertext);

        let mut packet = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        packet.extend_from_slice(nonce_bytes);
        packet.extend_from_slice(&ciphertext);
        packet
    }
}

// ---------------------------------------------------------------------------
// ObfuscatedUdpSocket — quinn AsyncUdpSocket wrapper
// ---------------------------------------------------------------------------

/// A UDP socket wrapper that transparently obfuscates/deobfuscates all
/// datagrams using [`PskObfuscator`].
///
/// Implements [`quinn::AsyncUdpSocket`] so it can be used as a drop-in
/// replacement for the real socket when constructing a `quinn::Endpoint`.
///
/// - **Send path**: each outgoing datagram is obfuscated (prepending an
///   8-byte nonce) before being forwarded to the inner socket.
/// - **Recv path**: each incoming datagram is deobfuscated (stripping the
///   nonce and decrypting) before being returned to quinn. Packets that
///   fail deobfuscation (too short) are silently dropped.
pub struct ObfuscatedUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfuscator: PskObfuscator,
}

impl ObfuscatedUdpSocket {
    /// Wrap an existing socket with PSK obfuscation.
    pub fn wrap(inner: Arc<dyn AsyncUdpSocket>, key: [u8; PSK_KEY_LEN]) -> Arc<Self> {
        Arc::new(Self {
            inner,
            obfuscator: PskObfuscator::new(key),
        })
    }
}

impl fmt::Debug for ObfuscatedUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfuscatedUdpSocket").field("inner", &self.inner).finish()
    }
}

impl AsyncUdpSocket for ObfuscatedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let obfuscated = self.obfuscator.obfuscate(transmit.contents);
        let wrapped = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &obfuscated,
            segment_size: None, // disable GSO for obfuscated packets
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&wrapped)
    }

    fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let poll = self.inner.poll_recv(cx, bufs, meta);
        match poll {
            Poll::Ready(Ok(count)) => {
                // Deobfuscate each received datagram in-place
                for i in 0..count {
                    let m = &mut meta[i];
                    let buf = &mut bufs[i];
                    let data = &buf[..m.len];

                    match self.obfuscator.deobfuscate(data) {
                        Ok(plaintext) => {
                            buf[..plaintext.len()].copy_from_slice(&plaintext);
                            let stripped = m.len - plaintext.len();
                            m.len = plaintext.len();
                            m.stride = m.stride.saturating_sub(stripped);
                        }
                        Err(_) => {
                            // Silently drop malformed packets by zeroing length
                            tracing::trace!(len = data.len(), "dropping packet: too short for PSK deobfuscation");
                            m.len = 0;
                            m.stride = 0;
                        }
                    }
                }
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        // Disable GSO when obfuscation is active — each datagram must be
        // individually wrapped with its own nonce.
        1
    }

    fn max_receive_segments(&self) -> usize {
        // Disable GRO — each datagram is individually deobfuscated.
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-DPI008.md, specs/frds/FRD-DPI009.md

    use super::*;

    // --- Test constants ---

    const TEST_KEY: [u8; PSK_KEY_LEN] = [0x42; PSK_KEY_LEN];
    const TEST_WRONG_KEY: [u8; PSK_KEY_LEN] = [0x99; PSK_KEY_LEN];
    const TEST_NONCE: [u8; NONCE_LEN] = [0xAA; NONCE_LEN];
    const TEST_PAYLOAD: &[u8] = b"QUIC packet payload";
    const TEST_SINGLE_BYTE: &[u8] = &[0xFF];
    const TEST_MTU_SIZE: usize = 1280;

    // --- T-1: Obfuscate returns nonce + ciphertext with correct lengths ---

    #[test]
    fn obfuscate_returns_correct_length() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let packet = obfuscator.obfuscate(TEST_PAYLOAD);

        assert_eq!(
            packet.len(),
            NONCE_LEN + TEST_PAYLOAD.len(),
            "packet length must be nonce + payload"
        );
    }

    // --- T-2: Deobfuscate roundtrip recovers original plaintext ---

    #[test]
    fn roundtrip_recovers_plaintext() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let packet = obfuscator.obfuscate(TEST_PAYLOAD);
        let recovered = obfuscator.deobfuscate(&packet).expect("deobfuscate");

        assert_eq!(recovered, TEST_PAYLOAD, "roundtrip must recover original");
    }

    // --- T-3: Packet too short (< 9 bytes) rejected ---

    #[test]
    fn deobfuscate_rejects_short_packet() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let short_packet = [0u8; NONCE_LEN]; // exactly 8 bytes — no payload

        let result = obfuscator.deobfuscate(&short_packet);
        assert_eq!(
            result,
            Err(PskError::PacketTooShort { len: NONCE_LEN }),
            "8-byte packet must be rejected"
        );
    }

    // --- T-4: Empty packet (0 bytes) rejected ---

    #[test]
    fn deobfuscate_rejects_empty_packet() {
        let obfuscator = PskObfuscator::new(TEST_KEY);

        let result = obfuscator.deobfuscate(&[]);
        assert_eq!(result, Err(PskError::PacketTooShort { len: 0 }), "empty packet must be rejected");
    }

    // --- T-5: Exactly 8 bytes rejected (nonce only, no payload) ---

    #[test]
    fn deobfuscate_rejects_nonce_only() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let nonce_only = [0xBB; NONCE_LEN];

        let result = obfuscator.deobfuscate(&nonce_only);
        assert!(result.is_err(), "nonce-only packet must be rejected");
    }

    // --- T-6: Different nonces produce different ciphertexts ---

    #[test]
    fn different_nonces_produce_different_ciphertexts() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let nonce_a = [0x01; NONCE_LEN];
        let nonce_b = [0x02; NONCE_LEN];

        let packet_a = obfuscator.obfuscate_with_nonce(&nonce_a, TEST_PAYLOAD);
        let packet_b = obfuscator.obfuscate_with_nonce(&nonce_b, TEST_PAYLOAD);

        // Nonces differ
        assert_ne!(&packet_a[..NONCE_LEN], &packet_b[..NONCE_LEN], "nonces must differ");

        // Ciphertexts differ
        assert_ne!(
            &packet_a[NONCE_LEN..],
            &packet_b[NONCE_LEN..],
            "ciphertexts with different nonces must differ"
        );
    }

    // --- T-7: Wrong PSK produces different decryption output ---

    #[test]
    fn wrong_key_produces_wrong_plaintext() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let wrong_obfuscator = PskObfuscator::new(TEST_WRONG_KEY);

        let packet = obfuscator.obfuscate(TEST_PAYLOAD);
        let wrong_result = wrong_obfuscator.deobfuscate(&packet).expect("deobfuscate");

        assert_ne!(
            wrong_result.as_slice(),
            TEST_PAYLOAD,
            "wrong key must not recover original plaintext"
        );
    }

    // --- T-8: Single-byte payload works (minimum valid case) ---

    #[test]
    fn single_byte_payload_roundtrip() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let packet = obfuscator.obfuscate(TEST_SINGLE_BYTE);

        assert_eq!(packet.len(), NONCE_LEN + 1, "single-byte packet length");

        let recovered = obfuscator.deobfuscate(&packet).expect("deobfuscate");
        assert_eq!(recovered, TEST_SINGLE_BYTE, "single-byte roundtrip");
    }

    // --- T-9: Large payload (MTU-sized, 1280 bytes) roundtrip ---

    #[test]
    fn mtu_sized_payload_roundtrip() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let payload = vec![0xAB; TEST_MTU_SIZE];
        let packet = obfuscator.obfuscate(&payload);

        assert_eq!(packet.len(), NONCE_LEN + TEST_MTU_SIZE, "MTU-sized packet length");

        let recovered = obfuscator.deobfuscate(&packet).expect("deobfuscate");
        assert_eq!(recovered, payload, "MTU-sized roundtrip");
    }

    // --- T-10: Roundtrip with deterministic nonce ---

    #[test]
    fn deterministic_nonce_roundtrip() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let packet = obfuscator.obfuscate_with_nonce(&TEST_NONCE, TEST_PAYLOAD);
        let recovered = obfuscator.deobfuscate(&packet).expect("deobfuscate");

        assert_eq!(recovered, TEST_PAYLOAD, "deterministic nonce roundtrip");
    }

    // --- T-11: Output is not plaintext (actually encrypted) ---

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let packet = obfuscator.obfuscate(TEST_PAYLOAD);
        let ciphertext = &packet[NONCE_LEN..];

        assert_ne!(ciphertext, TEST_PAYLOAD, "ciphertext must differ from plaintext");
    }

    // --- Additional: Two random obfuscations produce different packets ---

    #[test]
    fn random_obfuscations_differ() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let packet_a = obfuscator.obfuscate(TEST_PAYLOAD);
        let packet_b = obfuscator.obfuscate(TEST_PAYLOAD);

        // Extremely unlikely that two random 8-byte nonces are identical
        assert_ne!(packet_a, packet_b, "random obfuscations must differ");
    }

    // --- Additional: Deobfuscate with 7 bytes rejected ---

    #[test]
    fn deobfuscate_rejects_seven_bytes() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let result = obfuscator.deobfuscate(&[0u8; 7]);

        assert_eq!(result, Err(PskError::PacketTooShort { len: 7 }), "7-byte packet must be rejected");
    }

    // --- Additional: PskError display message ---

    #[test]
    fn psk_error_display() {
        let err = PskError::PacketTooShort { len: 5 };
        let msg = err.to_string();

        assert!(msg.contains("packet too short"), "error message must mention 'packet too short'");
        assert!(msg.contains('5'), "error message must contain actual length");
    }

    // --- Additional: Clone obfuscator produces same results ---

    #[test]
    fn cloned_obfuscator_produces_same_results() {
        let obfuscator = PskObfuscator::new(TEST_KEY);
        let cloned = obfuscator.clone();

        let packet = obfuscator.obfuscate_with_nonce(&TEST_NONCE, TEST_PAYLOAD);
        let recovered = cloned.deobfuscate(&packet).expect("deobfuscate");

        assert_eq!(recovered, TEST_PAYLOAD, "cloned obfuscator must work");
    }

    // ===================================================================
    // ObfuscatedUdpSocket tests
    // ===================================================================

    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Mock UDP socket that captures sent data and replays injected recv data.
    struct MockUdpSocket {
        /// Datagrams captured from `try_send`.
        sent: Mutex<Vec<Vec<u8>>>,
        /// Datagrams to return from `poll_recv`.
        recv_queue: Mutex<VecDeque<Vec<u8>>>,
        /// Local address to report.
        addr: SocketAddr,
    }

    impl MockUdpSocket {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                recv_queue: Mutex::new(VecDeque::new()),
                addr: "127.0.0.1:12345".parse().expect("valid addr"),
            }
        }

        fn push_recv(&self, data: Vec<u8>) {
            self.recv_queue.lock().expect("lock").push_back(data);
        }

        fn take_sent(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.sent.lock().expect("lock"))
        }
    }

    impl fmt::Debug for MockUdpSocket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockUdpSocket").finish()
        }
    }

    /// Trivial poller that always reports writable.
    struct AlwaysReady;

    impl fmt::Debug for AlwaysReady {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("AlwaysReady").finish()
        }
    }

    impl UdpPoller for AlwaysReady {
        fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncUdpSocket for MockUdpSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(AlwaysReady)
        }

        fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
            self.sent.lock().expect("lock").push(transmit.contents.to_vec());
            Ok(())
        }

        fn poll_recv(&self, _cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
            let mut queue = self.recv_queue.lock().expect("lock");
            if queue.is_empty() {
                return Poll::Pending;
            }

            let mut count = 0;
            for (i, data) in queue.drain(..).enumerate() {
                if i >= bufs.len() || i >= meta.len() {
                    break;
                }
                let len = data.len().min(bufs[i].len());
                bufs[i][..len].copy_from_slice(&data[..len]);
                meta[i] = RecvMeta {
                    addr: self.addr,
                    len,
                    stride: len,
                    ecn: None,
                    dst_ip: None,
                };
                count += 1;
            }
            Poll::Ready(Ok(count))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.addr)
        }
    }

    // --- Socket T-1: local_addr delegates to inner ---

    #[test]
    fn obfuscated_socket_delegates_local_addr() {
        let mock = Arc::new(MockUdpSocket::new());
        let socket = ObfuscatedUdpSocket::wrap(mock.clone(), TEST_KEY);

        let addr = socket.local_addr().expect("local_addr");
        assert_eq!(addr, mock.addr, "local_addr must delegate");
    }

    // --- Socket T-2: max_transmit_segments returns 1 ---

    #[test]
    fn obfuscated_socket_disables_gso() {
        let mock = Arc::new(MockUdpSocket::new());
        let socket = ObfuscatedUdpSocket::wrap(mock, TEST_KEY);

        assert_eq!(socket.max_transmit_segments(), 1, "GSO must be disabled");
    }

    // --- Socket T-3: max_receive_segments returns 1 ---

    #[test]
    fn obfuscated_socket_disables_gro() {
        let mock = Arc::new(MockUdpSocket::new());
        let socket = ObfuscatedUdpSocket::wrap(mock, TEST_KEY);

        assert_eq!(socket.max_receive_segments(), 1, "GRO must be disabled");
    }

    // --- Socket T-4: try_send obfuscates payload ---

    #[test]
    fn obfuscated_socket_try_send_obfuscates() {
        let mock = Arc::new(MockUdpSocket::new());
        let socket = ObfuscatedUdpSocket::wrap(mock.clone(), TEST_KEY);

        let transmit = Transmit {
            destination: "10.0.0.1:443".parse().expect("addr"),
            ecn: None,
            contents: TEST_PAYLOAD,
            segment_size: None,
            src_ip: None,
        };

        socket.try_send(&transmit).expect("try_send");

        let sent = mock.take_sent();
        assert_eq!(sent.len(), 1, "one packet must be sent");
        assert_ne!(sent[0].as_slice(), TEST_PAYLOAD, "sent data must be obfuscated");
    }

    // --- Socket T-5: try_send output is nonce + ciphertext ---

    #[test]
    fn obfuscated_socket_try_send_correct_length() {
        let mock = Arc::new(MockUdpSocket::new());
        let socket = ObfuscatedUdpSocket::wrap(mock.clone(), TEST_KEY);

        let transmit = Transmit {
            destination: "10.0.0.1:443".parse().expect("addr"),
            ecn: None,
            contents: TEST_PAYLOAD,
            segment_size: None,
            src_ip: None,
        };

        socket.try_send(&transmit).expect("try_send");

        let sent = mock.take_sent();
        assert_eq!(sent[0].len(), NONCE_LEN + TEST_PAYLOAD.len(), "sent length must be nonce + payload");
    }

    /// Create a no-op waker for synchronous `poll_recv` tests.
    ///
    /// The mock socket returns `Poll::Ready` immediately when data is
    /// queued, so the waker is never actually invoked.
    fn noop_waker() -> std::task::Waker {
        std::task::Waker::noop().clone()
    }

    // --- Socket T-6: send→recv roundtrip recovers original ---

    #[test]
    fn obfuscated_socket_send_recv_roundtrip() {
        let mock = Arc::new(MockUdpSocket::new());
        let socket = ObfuscatedUdpSocket::wrap(mock.clone(), TEST_KEY);

        // Send an obfuscated packet
        let transmit = Transmit {
            destination: "10.0.0.1:443".parse().expect("addr"),
            ecn: None,
            contents: TEST_PAYLOAD,
            segment_size: None,
            src_ip: None,
        };
        socket.try_send(&transmit).expect("try_send");

        // Inject the obfuscated packet into recv queue
        let sent = mock.take_sent();
        mock.push_recv(sent[0].clone());

        // Receive and deobfuscate
        let mut buf = [0u8; 2048];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut recv_meta = [RecvMeta::default()];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = socket.poll_recv(&mut cx, &mut iov, &mut recv_meta);
        let count = match poll {
            Poll::Ready(Ok(n)) => n,
            other => panic!("expected Ready(Ok), got {other:?}"),
        };

        assert_eq!(count, 1, "one packet received");
        assert_eq!(recv_meta[0].len, TEST_PAYLOAD.len(), "deobfuscated length");
        assert_eq!(&buf[..recv_meta[0].len], TEST_PAYLOAD, "roundtrip must recover original");
    }

    // --- Socket T-7: poll_recv drops too-short packets ---

    #[test]
    fn obfuscated_socket_drops_short_packets() {
        let mock = Arc::new(MockUdpSocket::new());
        let socket = ObfuscatedUdpSocket::wrap(mock.clone(), TEST_KEY);

        // Inject a packet that's too short (only 5 bytes)
        mock.push_recv(vec![0xAA; 5]);

        let mut buf = [0u8; 2048];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut recv_meta = [RecvMeta::default()];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = socket.poll_recv(&mut cx, &mut iov, &mut recv_meta);
        let count = match poll {
            Poll::Ready(Ok(n)) => n,
            other => panic!("expected Ready(Ok), got {other:?}"),
        };

        assert_eq!(count, 1, "packet count returned");
        assert_eq!(recv_meta[0].len, 0, "dropped packet must have zero length");
    }

    // --- Socket T-8: PSK nonce overhead constant ---

    #[test]
    fn psk_nonce_overhead_is_eight() {
        assert_eq!(PSK_NONCE_OVERHEAD, 8, "nonce overhead must be 8 bytes");
    }

    // --- Socket T-9: may_fragment delegates ---

    #[test]
    fn obfuscated_socket_delegates_may_fragment() {
        let mock = Arc::new(MockUdpSocket::new());
        let expected = mock.may_fragment();
        let socket = ObfuscatedUdpSocket::wrap(mock, TEST_KEY);

        assert_eq!(socket.may_fragment(), expected, "may_fragment must delegate");
    }

    // --- Socket T-10: Debug impl ---

    #[test]
    fn obfuscated_socket_debug() {
        let mock = Arc::new(MockUdpSocket::new());
        let socket = ObfuscatedUdpSocket::wrap(mock, TEST_KEY);

        let debug = format!("{socket:?}");
        assert!(debug.contains("ObfuscatedUdpSocket"), "debug output must contain type name");
    }
}
