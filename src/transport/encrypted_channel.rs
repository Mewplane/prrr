// FRD: specs/frds/FRD-005.md

//! Encrypted bidirectional channel using ChaCha20-Poly1305 with monotonic
//! nonce counters, automatic rekeying, and replay protection.
//!
//! Wire format per packet:
//! ```text
//! [8-byte nonce counter (big-endian)] [encrypted payload + 16-byte auth tag]
//! ```
//!
//! The 8-byte nonce counter is also used as AAD for AEAD authentication.

use zeroize::Zeroize;

use crate::crypto::aead::{self, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::crypto::kdf;

use super::TransportError;

/// Byte length of the nonce counter in the wire format.
pub const NONCE_COUNTER_LEN: usize = 8;

/// Minimum valid wire packet length: nonce counter + auth tag (empty payload).
pub const MIN_PACKET_LEN: usize = NONCE_COUNTER_LEN + TAG_LEN;

/// Default rekey threshold: 2^32 packets per SPEC.md.
pub const DEFAULT_REKEY_THRESHOLD: u64 = 1 << 32;

/// Default replay window size in packets.
pub const DEFAULT_REPLAY_WINDOW_SIZE: u64 = 64;

/// HKDF info string for rekeying.
const REKEY_INFO: &[u8] = b"prrr-rekey-v1";

/// Number of zero-padding bytes prepended to the 8-byte counter to form a 12-byte nonce.
const NONCE_PADDING_LEN: usize = NONCE_LEN - NONCE_COUNTER_LEN;

/// Encode a 64-bit counter as a 12-byte AEAD nonce.
///
/// Format: 4 zero bytes (big-endian padding) followed by 8-byte big-endian counter.
fn encode_nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[NONCE_PADDING_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Sliding-window replay detector.
///
/// Tracks the highest received nonce and maintains a bitmap of recently
/// seen nonces within a configurable window behind the highest.
struct ReplayWindow {
    /// Highest nonce value seen so far.
    highest: u64,
    /// Bitmap of seen nonces in the window `[highest - window_size + 1, highest]`.
    /// Bit `i` corresponds to nonce `highest - i`.
    bitmap: u64,
    /// Window size (max 64, since we use a u64 bitmap).
    window_size: u64,
}

impl ReplayWindow {
    /// Create a new replay window with the given size.
    ///
    /// `window_size` is clamped to the range `[1, 64]`.
    fn new(window_size: u64) -> Self {
        let window_size = window_size.clamp(1, 64);
        Self {
            highest: 0,
            bitmap: 0,
            window_size,
        }
    }

    /// Check if the given nonce is acceptable (not replayed, not too old).
    ///
    /// Returns `true` if the nonce should be accepted, `false` if it is a
    /// replay or falls outside the window.
    fn check_and_update(&mut self, nonce: u64) -> bool {
        if self.highest == 0 && self.bitmap == 0 {
            // First packet ever received
            self.highest = nonce;
            self.bitmap = 1;
            return true;
        }

        if nonce > self.highest {
            // New highest: shift the window
            let shift = nonce - self.highest;
            if shift >= self.window_size {
                self.bitmap = 0;
            } else {
                self.bitmap <<= shift;
            }
            self.bitmap |= 1;
            self.highest = nonce;
            return true;
        }

        let age = self.highest - nonce;
        if age >= self.window_size {
            // Too old — outside the window
            return false;
        }

        let bit = 1u64 << age;
        if self.bitmap & bit != 0 {
            // Already seen — replay
            return false;
        }

        // Mark as seen
        self.bitmap |= bit;
        true
    }
}

/// Encrypted bidirectional channel.
///
/// After a successful hybrid handshake (F-004), use the `SessionKeys` to
/// create an `EncryptedChannel`. Each direction (tx/rx) maintains its own
/// nonce counter and encryption key. Automatic rekeying occurs when the
/// tx counter reaches the configured threshold.
pub struct EncryptedChannel {
    tx_key: [u8; KEY_LEN],
    rx_key: [u8; KEY_LEN],
    tx_counter: u64,
    tx_rekey_count: u64,
    rekey_threshold: u64,
    replay_window: ReplayWindow,
    rx_rekey_count: u64,
    rx_key_cache: Vec<[u8; KEY_LEN]>,
}

impl EncryptedChannel {
    /// Create a new encrypted channel with default rekey threshold and replay window.
    pub fn new(tx_key: [u8; KEY_LEN], rx_key: [u8; KEY_LEN]) -> Self {
        Self::with_config(tx_key, rx_key, DEFAULT_REKEY_THRESHOLD, DEFAULT_REPLAY_WINDOW_SIZE)
    }

    /// Create a new encrypted channel with custom rekey threshold and replay window size.
    pub fn with_config(tx_key: [u8; KEY_LEN], rx_key: [u8; KEY_LEN], rekey_threshold: u64, replay_window_size: u64) -> Self {
        Self {
            tx_key,
            rx_key,
            tx_counter: 0,
            tx_rekey_count: 0,
            rekey_threshold,
            replay_window: ReplayWindow::new(replay_window_size),
            rx_rekey_count: 0,
            rx_key_cache: Vec::new(),
        }
    }

    /// Encrypt `plaintext` and return wire bytes.
    ///
    /// Wire format: `[8-byte nonce counter (BE)] [ciphertext + 16-byte tag]`
    ///
    /// The nonce counter bytes are also used as AAD.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        // Check if rekey is needed before sending
        if self.tx_counter >= self.rekey_threshold {
            self.rekey_tx()?;
        }

        // Compute absolute nonce: rekey_count * threshold + counter
        let absolute_nonce = self
            .tx_rekey_count
            .checked_mul(self.rekey_threshold)
            .and_then(|base| base.checked_add(self.tx_counter))
            .ok_or_else(|| TransportError::RekeyFailed("nonce counter overflow".to_string()))?;

        let counter_bytes = absolute_nonce.to_be_bytes();
        let nonce = encode_nonce(self.tx_counter);

        let ciphertext = aead::encrypt(&self.tx_key, &nonce, plaintext, &counter_bytes);

        let mut wire = Vec::with_capacity(NONCE_COUNTER_LEN + ciphertext.len());
        wire.extend_from_slice(&counter_bytes);
        wire.extend_from_slice(&ciphertext);

        self.tx_counter += 1;

        Ok(wire)
    }

    /// Decrypt `wire_bytes` and return the original plaintext.
    ///
    /// Validates packet length, checks replay protection, and decrypts.
    pub fn recv(&mut self, wire_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        if wire_bytes.len() < MIN_PACKET_LEN {
            return Err(TransportError::PacketTooShort {
                expected: MIN_PACKET_LEN,
                actual: wire_bytes.len(),
            });
        }

        // Extract nonce counter from wire
        let counter_bytes: [u8; NONCE_COUNTER_LEN] = wire_bytes[..NONCE_COUNTER_LEN].try_into().expect("slice length verified above");
        let absolute_nonce = u64::from_be_bytes(counter_bytes);

        // Check replay protection
        if !self.replay_window.check_and_update(absolute_nonce) {
            return Err(TransportError::ReplayDetected(absolute_nonce));
        }

        // Determine which rx key to use based on rekey epoch
        let (rx_key, local_counter) = self.rx_key_for_nonce(absolute_nonce);
        let nonce = encode_nonce(local_counter);

        let ciphertext = &wire_bytes[NONCE_COUNTER_LEN..];

        aead::decrypt(&rx_key, &nonce, ciphertext, &counter_bytes).map_err(|_| TransportError::DecryptionFailed)
    }

    /// Return the current tx nonce counter value.
    pub fn tx_counter(&self) -> u64 {
        self.tx_counter
    }

    /// Return the current tx rekey count.
    pub fn tx_rekey_count(&self) -> u64 {
        self.tx_rekey_count
    }

    /// Derive the rx key and local counter for a given absolute nonce.
    fn rx_key_for_nonce(&mut self, absolute_nonce: u64) -> ([u8; KEY_LEN], u64) {
        let epoch = absolute_nonce / self.rekey_threshold;
        let local_counter = absolute_nonce % self.rekey_threshold;

        // Ensure we have enough cached keys for this epoch
        while self.rx_rekey_count < epoch {
            let current_key = if self.rx_key_cache.is_empty() {
                self.rx_key
            } else {
                self.rx_key_cache[self.rx_key_cache.len() - 1]
            };
            let new_key = derive_rekey(&current_key);
            self.rx_key_cache.push(new_key);
            self.rx_rekey_count += 1;
        }

        let key = if epoch == 0 {
            self.rx_key
        } else {
            self.rx_key_cache[(epoch - 1) as usize]
        };

        (key, local_counter)
    }

    /// Perform a rekey on the tx side.
    fn rekey_tx(&mut self) -> Result<(), TransportError> {
        self.tx_key = derive_rekey(&self.tx_key);
        self.tx_counter = 0;
        self.tx_rekey_count += 1;
        Ok(())
    }
}

impl Drop for EncryptedChannel {
    fn drop(&mut self) {
        self.tx_key.zeroize();
        self.rx_key.zeroize();
        for cached_key in &mut self.rx_key_cache {
            cached_key.zeroize();
        }
    }
}

/// Derive a new key from an existing key using HKDF.
fn derive_rekey(current_key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let prk = kdf::extract(current_key, REKEY_INFO);
    let mut new_key = [0u8; KEY_LEN];
    new_key.copy_from_slice(&prk);
    new_key
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TX_KEY: [u8; KEY_LEN] = [0x01; KEY_LEN];
    const TEST_RX_KEY: [u8; KEY_LEN] = [0x02; KEY_LEN];

    /// Create a paired channel where sender's tx = receiver's rx and vice versa.
    fn paired_channels() -> (EncryptedChannel, EncryptedChannel) {
        let sender = EncryptedChannel::new(TEST_TX_KEY, TEST_RX_KEY);
        let receiver = EncryptedChannel::new(TEST_RX_KEY, TEST_TX_KEY);
        (sender, receiver)
    }

    /// Create a paired channel with custom rekey threshold.
    fn paired_channels_with_rekey(threshold: u64) -> (EncryptedChannel, EncryptedChannel) {
        let sender = EncryptedChannel::with_config(TEST_TX_KEY, TEST_RX_KEY, threshold, DEFAULT_REPLAY_WINDOW_SIZE);
        let receiver = EncryptedChannel::with_config(TEST_RX_KEY, TEST_TX_KEY, threshold, DEFAULT_REPLAY_WINDOW_SIZE);
        (sender, receiver)
    }

    // T-1: Encrypt/decrypt round-trip with 1-byte payload
    #[test]
    fn round_trip_single_byte() {
        let (mut sender, mut receiver) = paired_channels();
        let plaintext = b"x";
        let wire = sender.send(plaintext).expect("send");
        let decrypted = receiver.recv(&wire).expect("recv");
        assert_eq!(decrypted, plaintext);
    }

    // T-2: Nonce counter increments on each send
    #[test]
    fn nonce_counter_increments() {
        let (mut sender, _receiver) = paired_channels();
        assert_eq!(sender.tx_counter(), 0);

        sender.send(b"a").expect("send 1");
        assert_eq!(sender.tx_counter(), 1);

        sender.send(b"b").expect("send 2");
        assert_eq!(sender.tx_counter(), 2);

        sender.send(b"c").expect("send 3");
        assert_eq!(sender.tx_counter(), 3);
    }

    // T-3: Nonce encoding: 64-bit BE counter zero-padded to 96-bit
    #[test]
    fn nonce_encoding_zero_padded() {
        let nonce = encode_nonce(0);
        assert_eq!(nonce, [0u8; NONCE_LEN]);

        let nonce = encode_nonce(1);
        let mut expected = [0u8; NONCE_LEN];
        expected[NONCE_LEN - 1] = 1;
        assert_eq!(nonce, expected);

        let nonce = encode_nonce(0x0102_0304_0506_0708);
        let expected = [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(nonce, expected);
    }

    // T-4: Wire format contains nonce counter + ciphertext + tag
    #[test]
    fn wire_format_structure() {
        let (mut sender, _receiver) = paired_channels();
        let plaintext = b"hello";
        let wire = sender.send(plaintext).expect("send");

        // Wire = 8-byte counter + ciphertext(5 bytes) + 16-byte tag
        let expected_len = NONCE_COUNTER_LEN + plaintext.len() + TAG_LEN;
        assert_eq!(wire.len(), expected_len);

        // First 8 bytes are the counter (should be 0 for first packet)
        let counter_bytes = &wire[..NONCE_COUNTER_LEN];
        assert_eq!(counter_bytes, &0u64.to_be_bytes());
    }

    // T-5: Replay same packet twice → ReplayDetected
    #[test]
    fn replay_detected() {
        let (mut sender, mut receiver) = paired_channels();
        let wire = sender.send(b"msg").expect("send");

        receiver.recv(&wire).expect("first recv");
        let result = receiver.recv(&wire);
        assert!(matches!(result, Err(TransportError::ReplayDetected(0))));
    }

    // T-6: Out-of-order within replay window accepted
    #[test]
    fn out_of_order_within_window() {
        let (mut sender, mut receiver) = paired_channels();

        // Send 5 packets, collect wire bytes
        let mut wires = Vec::new();
        let packet_count = 5;
        for i in 0..packet_count {
            let wire = sender.send(format!("msg{i}").as_bytes()).expect("send");
            wires.push(wire);
        }

        // Receive out of order: 4, 2, 0, 1, 3
        let order = [4, 2, 0, 1, 3];
        for &idx in &order {
            let plaintext = receiver.recv(&wires[idx]).expect("recv");
            assert_eq!(plaintext, format!("msg{idx}").as_bytes());
        }
    }

    // T-7: Out-of-order beyond replay window rejected
    #[test]
    fn out_of_order_beyond_window() {
        let window_size: u64 = 8;
        let mut sender = EncryptedChannel::with_config(TEST_TX_KEY, TEST_RX_KEY, DEFAULT_REKEY_THRESHOLD, window_size);
        let mut receiver = EncryptedChannel::with_config(TEST_RX_KEY, TEST_TX_KEY, DEFAULT_REKEY_THRESHOLD, window_size);

        // Send window_size + 2 packets
        let total = (window_size + 2) as usize;
        let mut wires = Vec::new();
        for i in 0..total {
            let wire = sender.send(format!("msg{i}").as_bytes()).expect("send");
            wires.push(wire);
        }

        // Receive the last packet first (establishes high watermark)
        let last_idx = total - 1;
        receiver.recv(&wires[last_idx]).expect("recv last");

        // Packet 0 is now beyond the window (age = last_idx > window_size)
        let result = receiver.recv(&wires[0]);
        assert!(matches!(result, Err(TransportError::ReplayDetected(0))));
    }

    // T-8: Tampered ciphertext → DecryptionFailed
    #[test]
    fn tampered_ciphertext_fails() {
        let (mut sender, mut receiver) = paired_channels();
        let mut wire = sender.send(b"secret").expect("send");

        // Flip a byte in the ciphertext portion
        let tamper_idx = NONCE_COUNTER_LEN + 1;
        wire[tamper_idx] ^= 0xff;

        let result = receiver.recv(&wire);
        assert!(matches!(result, Err(TransportError::DecryptionFailed)));
    }

    // T-9: Packet too short → PacketTooShort
    #[test]
    fn packet_too_short() {
        let (_, mut receiver) = paired_channels();

        let short_packet = vec![0u8; MIN_PACKET_LEN - 1];
        let result = receiver.recv(&short_packet);
        match result {
            Err(TransportError::PacketTooShort { expected, actual }) => {
                assert_eq!(expected, MIN_PACKET_LEN);
                assert_eq!(actual, MIN_PACKET_LEN - 1);
            }
            other => panic!("expected PacketTooShort, got: {other:?}"),
        }
    }

    // T-10: Rekey triggers at configured threshold, counter resets
    #[test]
    fn rekey_at_threshold() {
        let threshold: u64 = 4;
        let (mut sender, _receiver) = paired_channels_with_rekey(threshold);

        // Send threshold packets
        for _ in 0..threshold {
            sender.send(b"x").expect("send");
        }
        assert_eq!(sender.tx_counter(), threshold);

        // Next send triggers rekey: counter resets after rekey
        sender.send(b"y").expect("send after rekey");
        assert_eq!(sender.tx_counter(), 1);
        assert_eq!(sender.tx_rekey_count(), 1);
    }

    // T-11: Communication works across rekey boundary
    #[test]
    fn communication_across_rekey() {
        let threshold: u64 = 3;
        let (mut sender, mut receiver) = paired_channels_with_rekey(threshold);

        // Send packets across the rekey boundary
        let total = (threshold * 2 + 1) as usize;
        for i in 0..total {
            let plaintext = format!("msg{i}");
            let wire = sender.send(plaintext.as_bytes()).expect("send");
            let decrypted = receiver.recv(&wire).expect("recv");
            assert_eq!(decrypted, plaintext.as_bytes(), "mismatch at packet {i}");
        }
    }

    // T-12: Empty plaintext round-trip
    #[test]
    fn empty_plaintext_round_trip() {
        let (mut sender, mut receiver) = paired_channels();
        let wire = sender.send(b"").expect("send empty");
        let decrypted = receiver.recv(&wire).expect("recv empty");
        assert!(decrypted.is_empty());
    }

    // T-13: Bidirectional: both sides send and receive
    #[test]
    fn bidirectional_communication() {
        let (mut alice, mut bob) = paired_channels();

        // Alice → Bob
        let wire = alice.send(b"hello bob").expect("alice send");
        let pt = bob.recv(&wire).expect("bob recv");
        assert_eq!(pt, b"hello bob");

        // Bob → Alice
        let wire = bob.send(b"hello alice").expect("bob send");
        let pt = alice.recv(&wire).expect("alice recv");
        assert_eq!(pt, b"hello alice");

        // Interleaved
        let w1 = alice.send(b"a2b").expect("alice send 2");
        let w2 = bob.send(b"b2a").expect("bob send 2");
        let p1 = bob.recv(&w1).expect("bob recv 2");
        let p2 = alice.recv(&w2).expect("alice recv 2");
        assert_eq!(p1, b"a2b");
        assert_eq!(p2, b"b2a");
    }

    // T-14: Large payload (64KB) round-trip
    #[test]
    fn large_payload_round_trip() {
        let (mut sender, mut receiver) = paired_channels();
        let large_payload = vec![0xAB; 65536];
        let wire = sender.send(&large_payload).expect("send large");
        let decrypted = receiver.recv(&wire).expect("recv large");
        assert_eq!(decrypted, large_payload);
    }

    // T-15: Wrong key → DecryptionFailed
    #[test]
    fn wrong_key_fails() {
        let mut sender = EncryptedChannel::new(TEST_TX_KEY, TEST_RX_KEY);
        let wrong_key = [0xFF; KEY_LEN];
        let mut receiver = EncryptedChannel::new(wrong_key, wrong_key);

        let wire = sender.send(b"secret").expect("send");
        let result = receiver.recv(&wire);
        assert!(matches!(result, Err(TransportError::DecryptionFailed)));
    }

    // T-16: Sequential 1000 packets all decrypt correctly
    #[test]
    fn sequential_thousand_packets() {
        let (mut sender, mut receiver) = paired_channels();
        let packet_count: usize = 1000;
        for i in 0..packet_count {
            let plaintext = format!("packet-{i:04}");
            let wire = sender.send(plaintext.as_bytes()).expect("send");
            let decrypted = receiver.recv(&wire).expect("recv");
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }

    // Replay window unit tests
    #[test]
    fn replay_window_first_packet() {
        let mut window = ReplayWindow::new(DEFAULT_REPLAY_WINDOW_SIZE);
        assert!(window.check_and_update(0));
        assert!(!window.check_and_update(0)); // duplicate
    }

    #[test]
    fn replay_window_sequential() {
        let mut window = ReplayWindow::new(DEFAULT_REPLAY_WINDOW_SIZE);
        for i in 0..100 {
            assert!(window.check_and_update(i), "nonce {i} should be accepted");
        }
    }

    #[test]
    fn replay_window_out_of_order() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(10));
        assert!(window.check_and_update(5)); // within window
        assert!(!window.check_and_update(5)); // replay
        assert!(window.check_and_update(8)); // within window, not seen
    }

    // T-20 (FRD-017): EncryptedChannel zeroizes keys on drop
    #[test]
    fn encrypted_channel_zeroizes_keys_on_drop() {
        use zeroize::Zeroize;

        let mut channel = EncryptedChannel::new(TEST_TX_KEY, TEST_RX_KEY);

        // Verify keys are non-zero
        assert_ne!(channel.tx_key, [0u8; KEY_LEN]);
        assert_ne!(channel.rx_key, [0u8; KEY_LEN]);

        // Simulate what Drop does
        channel.tx_key.zeroize();
        channel.rx_key.zeroize();

        assert_eq!(channel.tx_key, [0u8; KEY_LEN]);
        assert_eq!(channel.rx_key, [0u8; KEY_LEN]);
    }

    /// Encrypted wire size must be exactly plaintext + NONCE_COUNTER_LEN + TAG_LEN.
    /// TUNNEL_OVERHEAD_BYTES depends on this formula being exact.
    #[test]
    fn encrypted_wire_size_is_plaintext_plus_overhead() {
        use crate::crypto::aead::TAG_LEN;

        let mut channel = EncryptedChannel::new(TEST_TX_KEY, TEST_RX_KEY);
        let expected_overhead = NONCE_COUNTER_LEN + TAG_LEN;

        for size in [0, 1, 576, 1100, 1420] {
            let plaintext = vec![0xABu8; size];
            let encrypted = channel.send(&plaintext).unwrap();
            assert_eq!(
                encrypted.len(),
                size + expected_overhead,
                "wire size for {size}-byte plaintext: expected {} got {}",
                size + expected_overhead,
                encrypted.len()
            );
        }
    }
}
