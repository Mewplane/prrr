// FRD: specs/frds/FRD-011.md

//! Traffic morphing: packet padding, timing jitter, and dummy traffic.
//!
//! Provides configurable padding strategies to normalize packet sizes,
//! a timing jitter utility, and dummy packet generation. The morpher
//! operates at the byte level — pad before encryption, unpad after
//! decryption.
//!
//! # Wire Format (Padded Frame)
//!
//! ```text
//! [2-byte payload length (BE)] [payload bytes] [random padding bytes]
//! ```
//!
//! Unpadding is strategy-independent: the receiver reads the 2-byte length
//! header and extracts exactly that many payload bytes, ignoring any trailing
//! padding.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use rand::Rng;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the payload length header in bytes.
const HEADER_LEN: usize = 2;

/// Maximum payload size (limited by 2-byte BE length header).
const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

/// Minimum padded frame size for PowerOfTwo strategy.
const POWER_OF_TWO_MIN_SIZE: usize = 4;

/// Common HTTP response sizes used by the `HttpSizes` padding strategy.
/// These approximate typical HTTP response payload sizes observed in web traffic.
const HTTP_TARGET_SIZES: [usize; 5] = [128, 256, 512, 1024, 1460];

/// Dummy packet payload length value (zero means no real payload).
const DUMMY_PAYLOAD_LEN: u16 = 0;

/// Minimum padded frame size for dummy packets.
const DUMMY_MIN_FRAME_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by traffic morphing operations.
#[derive(Debug, thiserror::Error)]
pub enum MorphError {
    /// The padded frame is too short to contain the 2-byte length header.
    #[error("frame too short: need at least {HEADER_LEN} bytes, got {actual}")]
    FrameTooShort {
        /// Actual frame length received.
        actual: usize,
    },

    /// The payload length in the header exceeds the remaining frame bytes.
    #[error("payload length {payload_len} exceeds frame capacity {available}")]
    PayloadLengthExceedsFrame {
        /// Declared payload length from the header.
        payload_len: usize,
        /// Available bytes after the header.
        available: usize,
    },

    /// The payload exceeds the maximum size (65535 bytes).
    #[error("payload too large: {size} bytes exceeds maximum {MAX_PAYLOAD_LEN}")]
    PayloadTooLarge {
        /// Actual payload size.
        size: usize,
    },
}

// ---------------------------------------------------------------------------
// Padding Strategy
// ---------------------------------------------------------------------------

/// Padding strategy for traffic morphing.
///
/// Controls how the total padded frame size is computed from the payload size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaddingStrategy {
    /// Pad to the next power of 2 (minimum 4 bytes).
    PowerOfTwo,

    /// Pad to the nearest common HTTP response size.
    HttpSizes,

    /// Pad to a fixed MTU size.
    FixedMtu(u16),

    /// No padding — only the 2-byte length header is added.
    None,
}

/// Display name for PowerOfTwo strategy.
const STRATEGY_NAME_POWER_OF_TWO: &str = "power-of-two";

/// Display name for HttpSizes strategy.
const STRATEGY_NAME_HTTP_SIZES: &str = "http-sizes";

/// Display name prefix for FixedMtu strategy.
const STRATEGY_NAME_FIXED_MTU_PREFIX: &str = "fixed-mtu:";

/// Display name for None strategy.
const STRATEGY_NAME_NONE: &str = "none";

impl fmt::Display for PaddingStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PowerOfTwo => f.write_str(STRATEGY_NAME_POWER_OF_TWO),
            Self::HttpSizes => f.write_str(STRATEGY_NAME_HTTP_SIZES),
            Self::FixedMtu(mtu) => write!(f, "{STRATEGY_NAME_FIXED_MTU_PREFIX}{mtu}"),
            Self::None => f.write_str(STRATEGY_NAME_NONE),
        }
    }
}

/// Error returned when parsing an unknown padding strategy name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePaddingStrategyError {
    /// The unknown strategy name that was provided.
    pub unknown: String,
}

impl fmt::Display for ParsePaddingStrategyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown padding strategy: '{}'", self.unknown)
    }
}

impl std::error::Error for ParsePaddingStrategyError {}

impl FromStr for PaddingStrategy {
    type Err = ParsePaddingStrategyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_lowercase();
        if lower == STRATEGY_NAME_POWER_OF_TWO {
            Ok(Self::PowerOfTwo)
        } else if lower == STRATEGY_NAME_HTTP_SIZES {
            Ok(Self::HttpSizes)
        } else if lower == STRATEGY_NAME_NONE {
            Ok(Self::None)
        } else if let Some(mtu_str) = lower.strip_prefix(STRATEGY_NAME_FIXED_MTU_PREFIX) {
            let mtu: u16 = mtu_str.parse().map_err(|_| ParsePaddingStrategyError { unknown: s.to_string() })?;
            Ok(Self::FixedMtu(mtu))
        } else {
            Err(ParsePaddingStrategyError { unknown: s.to_string() })
        }
    }
}

// ---------------------------------------------------------------------------
// TrafficMorpher
// ---------------------------------------------------------------------------

/// Traffic morpher that adds and removes padding from payloads.
///
/// Padding format: `[2-byte payload length (BE)] [payload] [random padding]`.
/// Unpadding is strategy-independent — it reads the 2-byte length header.
#[derive(Debug, Clone)]
pub struct TrafficMorpher {
    strategy: PaddingStrategy,
}

impl TrafficMorpher {
    /// Create a new traffic morpher with the given padding strategy.
    pub fn new(strategy: PaddingStrategy) -> Self {
        Self { strategy }
    }

    /// Return the padding strategy in use.
    pub fn strategy(&self) -> PaddingStrategy {
        self.strategy
    }

    /// Pad a payload according to the configured strategy.
    ///
    /// Returns a framed buffer: `[2-byte payload length (BE)] [payload] [random padding]`.
    pub fn pad(&self, payload: &[u8]) -> Result<Vec<u8>, MorphError> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(MorphError::PayloadTooLarge { size: payload.len() });
        }

        let unpadded_size = HEADER_LEN + payload.len();
        let padded_size = self.compute_padded_size(unpadded_size);

        let mut frame = Vec::with_capacity(padded_size + HEADER_LEN);

        // 2-byte payload length header (big-endian)
        let len_bytes = (payload.len() as u16).to_be_bytes();
        frame.extend_from_slice(&len_bytes);

        // Payload
        frame.extend_from_slice(payload);

        // Random padding to fill to padded_size
        let padding_needed = padded_size - unpadded_size;
        if padding_needed > 0 {
            let mut padding = vec![0u8; padding_needed];
            rand::thread_rng().fill(&mut padding[..]);
            frame.extend_from_slice(&padding);
        }

        Ok(frame)
    }

    /// Remove padding from a framed buffer and return the original payload.
    ///
    /// This is strategy-independent: reads the 2-byte length header and
    /// extracts exactly that many bytes as payload.
    pub fn unpad(framed: &[u8]) -> Result<Vec<u8>, MorphError> {
        unpad(framed)
    }

    /// Compute the padded frame size for a given unpadded size.
    fn compute_padded_size(&self, unpadded_size: usize) -> usize {
        match self.strategy {
            PaddingStrategy::PowerOfTwo => {
                let min_size = unpadded_size.max(POWER_OF_TWO_MIN_SIZE);
                let next = min_size.next_power_of_two();
                // Avoid padding to 2048 or larger, which exceeds standard QUIC datagram size
                if next > 1280 { unpadded_size } else { next }
            }
            PaddingStrategy::HttpSizes => {
                for &target in &HTTP_TARGET_SIZES {
                    if target >= unpadded_size {
                        return target;
                    }
                }
                // Payload exceeds all targets — no padding
                unpadded_size
            }
            PaddingStrategy::FixedMtu(mtu) => {
                let mtu_size = usize::from(mtu);
                if unpadded_size <= mtu_size {
                    mtu_size
                } else {
                    // Payload exceeds MTU — no padding
                    unpadded_size
                }
            }
            PaddingStrategy::None => unpadded_size,
        }
    }
}

/// Remove padding from a framed buffer (strategy-independent).
///
/// Reads the 2-byte big-endian length header and extracts exactly that many
/// payload bytes. Any trailing bytes (padding) are discarded.
pub fn unpad(framed: &[u8]) -> Result<Vec<u8>, MorphError> {
    if framed.len() < HEADER_LEN {
        return Err(MorphError::FrameTooShort { actual: framed.len() });
    }

    let payload_len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
    let available = framed.len() - HEADER_LEN;

    if payload_len > available {
        return Err(MorphError::PayloadLengthExceedsFrame { payload_len, available });
    }

    Ok(framed[HEADER_LEN..HEADER_LEN + payload_len].to_vec())
}

// ---------------------------------------------------------------------------
// Dummy Packets
// ---------------------------------------------------------------------------

/// Check if a framed buffer is a dummy packet (payload length = 0).
pub fn is_dummy_packet(framed: &[u8]) -> bool {
    if framed.len() < HEADER_LEN {
        return false;
    }
    u16::from_be_bytes([framed[0], framed[1]]) == DUMMY_PAYLOAD_LEN
}

/// Generate a dummy packet with the given padding strategy.
///
/// A dummy packet has payload length 0 and is filled with random padding.
/// It is indistinguishable from a real encrypted packet on the wire.
pub fn generate_dummy(strategy: PaddingStrategy) -> Vec<u8> {
    let morpher = TrafficMorpher::new(strategy);
    let unpadded_size = HEADER_LEN; // header only, no payload
    let padded_size = match strategy {
        PaddingStrategy::None => DUMMY_MIN_FRAME_SIZE.max(unpadded_size),
        _ => morpher.compute_padded_size(unpadded_size).max(DUMMY_MIN_FRAME_SIZE),
    };

    let mut frame = Vec::with_capacity(padded_size);

    // 2-byte payload length = 0 (dummy marker)
    frame.extend_from_slice(&DUMMY_PAYLOAD_LEN.to_be_bytes());

    // Random padding
    let padding_needed = padded_size - HEADER_LEN;
    let mut padding = vec![0u8; padding_needed];
    rand::thread_rng().fill(&mut padding[..]);
    frame.extend_from_slice(&padding);

    frame
}

// ---------------------------------------------------------------------------
// Timing Jitter
// ---------------------------------------------------------------------------

/// Compute a random jitter duration from a uniform distribution `[0, max_ms)`.
///
/// Returns `Duration::ZERO` if `max_ms` is 0.
pub fn compute_jitter(max_ms: u64) -> Duration {
    if max_ms == 0 {
        return Duration::ZERO;
    }
    let ms = rand::thread_rng().gen_range(0..max_ms);
    Duration::from_millis(ms)
}

// ---------------------------------------------------------------------------
// MorphConfig
// ---------------------------------------------------------------------------

/// Convenience configuration for traffic morphing.
///
/// Bundles the padding strategy and maximum jitter for easy passing around.
#[derive(Debug, Clone)]
pub struct MorphConfig {
    /// Padding strategy to use.
    pub strategy: PaddingStrategy,

    /// Maximum timing jitter in milliseconds. 0 = no jitter.
    pub max_jitter_ms: u64,
}

/// Default maximum jitter in milliseconds per SPEC.md.
const DEFAULT_MAX_JITTER_MS: u64 = 50;

impl MorphConfig {
    /// Create a new morph config with the given strategy and jitter.
    pub fn new(strategy: PaddingStrategy, max_jitter_ms: u64) -> Self {
        Self { strategy, max_jitter_ms }
    }

    /// Create a default config: PowerOfTwo padding, 50ms max jitter.
    pub fn default_config() -> Self {
        Self {
            strategy: PaddingStrategy::PowerOfTwo,
            max_jitter_ms: DEFAULT_MAX_JITTER_MS,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only constants
    const SMALL_PAYLOAD: &[u8] = b"hello";
    const MEDIUM_PAYLOAD_SIZE: usize = 100;
    const LARGE_PAYLOAD_SIZE: usize = 1400;
    const FIXED_MTU_VALUE: u16 = 1500;
    const JITTER_MAX_MS: u64 = 50;
    const JITTER_SAMPLE_COUNT: usize = 100;
    const RANDOMNESS_SAMPLE_COUNT: usize = 10;

    fn medium_payload() -> Vec<u8> {
        vec![0xAB; MEDIUM_PAYLOAD_SIZE]
    }

    fn large_payload() -> Vec<u8> {
        vec![0xCD; LARGE_PAYLOAD_SIZE]
    }

    // -----------------------------------------------------------------------
    // T-1: PowerOfTwo pad/unpad round-trip for various payload sizes
    // -----------------------------------------------------------------------

    #[test]
    fn power_of_two_round_trip_small() {
        let morpher = TrafficMorpher::new(PaddingStrategy::PowerOfTwo);
        let framed = morpher.pad(SMALL_PAYLOAD).expect("pad");
        let recovered = TrafficMorpher::unpad(&framed).expect("unpad");
        assert_eq!(recovered, SMALL_PAYLOAD);
    }

    #[test]
    fn power_of_two_round_trip_medium() {
        let morpher = TrafficMorpher::new(PaddingStrategy::PowerOfTwo);
        let payload = medium_payload();
        let framed = morpher.pad(&payload).expect("pad");
        let recovered = TrafficMorpher::unpad(&framed).expect("unpad");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn power_of_two_round_trip_large() {
        let morpher = TrafficMorpher::new(PaddingStrategy::PowerOfTwo);
        let payload = large_payload();
        let framed = morpher.pad(&payload).expect("pad");
        let recovered = TrafficMorpher::unpad(&framed).expect("unpad");
        assert_eq!(recovered, payload);
    }

    // -----------------------------------------------------------------------
    // T-2: HttpSizes pad/unpad round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn http_sizes_round_trip_small() {
        let morpher = TrafficMorpher::new(PaddingStrategy::HttpSizes);
        let framed = morpher.pad(SMALL_PAYLOAD).expect("pad");
        let recovered = TrafficMorpher::unpad(&framed).expect("unpad");
        assert_eq!(recovered, SMALL_PAYLOAD);
    }

    #[test]
    fn http_sizes_round_trip_medium() {
        let morpher = TrafficMorpher::new(PaddingStrategy::HttpSizes);
        let payload = medium_payload();
        let framed = morpher.pad(&payload).expect("pad");
        let recovered = TrafficMorpher::unpad(&framed).expect("unpad");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn http_sizes_round_trip_large() {
        let morpher = TrafficMorpher::new(PaddingStrategy::HttpSizes);
        let payload = large_payload();
        let framed = morpher.pad(&payload).expect("pad");
        let recovered = TrafficMorpher::unpad(&framed).expect("unpad");
        assert_eq!(recovered, payload);
    }

    // -----------------------------------------------------------------------
    // T-3: FixedMtu pad/unpad round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn fixed_mtu_round_trip() {
        let morpher = TrafficMorpher::new(PaddingStrategy::FixedMtu(FIXED_MTU_VALUE));
        let framed = morpher.pad(SMALL_PAYLOAD).expect("pad");
        let recovered = TrafficMorpher::unpad(&framed).expect("unpad");
        assert_eq!(recovered, SMALL_PAYLOAD);
        assert_eq!(framed.len(), usize::from(FIXED_MTU_VALUE));
    }

    // -----------------------------------------------------------------------
    // T-4: None strategy produces minimal frame
    // -----------------------------------------------------------------------

    #[test]
    fn none_strategy_minimal_frame() {
        let morpher = TrafficMorpher::new(PaddingStrategy::None);
        let framed = morpher.pad(SMALL_PAYLOAD).expect("pad");
        let recovered = TrafficMorpher::unpad(&framed).expect("unpad");
        assert_eq!(recovered, SMALL_PAYLOAD);
        assert_eq!(framed.len(), HEADER_LEN + SMALL_PAYLOAD.len());
    }

    // -----------------------------------------------------------------------
    // T-5: Empty payload pad/unpad round-trip (all strategies)
    // -----------------------------------------------------------------------

    #[test]
    fn empty_payload_all_strategies() {
        let strategies = [
            PaddingStrategy::PowerOfTwo,
            PaddingStrategy::HttpSizes,
            PaddingStrategy::FixedMtu(FIXED_MTU_VALUE),
            PaddingStrategy::None,
        ];
        for strategy in strategies {
            let morpher = TrafficMorpher::new(strategy);
            let framed = morpher.pad(b"").expect("pad");
            let recovered = TrafficMorpher::unpad(&framed).expect("unpad");
            assert!(recovered.is_empty(), "empty payload round-trip failed for {strategy}");
        }
    }

    // -----------------------------------------------------------------------
    // T-6: Dummy packet generation and detection
    // -----------------------------------------------------------------------

    #[test]
    fn dummy_packet_generation_and_detection() {
        let strategies = [
            PaddingStrategy::PowerOfTwo,
            PaddingStrategy::HttpSizes,
            PaddingStrategy::FixedMtu(FIXED_MTU_VALUE),
            PaddingStrategy::None,
        ];
        for strategy in strategies {
            let dummy = generate_dummy(strategy);
            assert!(is_dummy_packet(&dummy), "dummy packet should be detected for {strategy}");
            assert!(
                dummy.len() >= DUMMY_MIN_FRAME_SIZE,
                "dummy packet should be at least {DUMMY_MIN_FRAME_SIZE} bytes for {strategy}"
            );

            // Unpad should return empty payload
            let payload = unpad(&dummy).expect("unpad dummy");
            assert!(payload.is_empty(), "dummy payload should be empty for {strategy}");
        }
    }

    #[test]
    fn real_packet_not_detected_as_dummy() {
        let morpher = TrafficMorpher::new(PaddingStrategy::PowerOfTwo);
        let framed = morpher.pad(SMALL_PAYLOAD).expect("pad");
        assert!(!is_dummy_packet(&framed), "real packet should not be detected as dummy");
    }

    // -----------------------------------------------------------------------
    // T-7: Padding bytes are non-deterministic (random)
    // -----------------------------------------------------------------------

    #[test]
    fn padding_bytes_are_random() {
        let morpher = TrafficMorpher::new(PaddingStrategy::FixedMtu(FIXED_MTU_VALUE));
        let mut frames: Vec<Vec<u8>> = Vec::new();

        for _ in 0..RANDOMNESS_SAMPLE_COUNT {
            frames.push(morpher.pad(SMALL_PAYLOAD).expect("pad"));
        }

        // Check that not all padding bytes are identical across samples.
        // Compare the padding region (after header + payload) of each pair.
        let padding_start = HEADER_LEN + SMALL_PAYLOAD.len();
        let mut all_identical = true;
        for i in 1..frames.len() {
            if frames[i][padding_start..] != frames[0][padding_start..] {
                all_identical = false;
                break;
            }
        }
        assert!(!all_identical, "padding should be random across {RANDOMNESS_SAMPLE_COUNT} samples");
    }

    // -----------------------------------------------------------------------
    // T-8: PowerOfTwo sizes are actually powers of 2
    // -----------------------------------------------------------------------

    #[test]
    fn power_of_two_sizes_are_powers() {
        let morpher = TrafficMorpher::new(PaddingStrategy::PowerOfTwo);
        let test_sizes: [usize; 6] = [1, 5, 13, 100, 500, 1022];

        for &size in &test_sizes {
            let payload = vec![0xAA; size];
            let framed = morpher.pad(&payload).expect("pad");
            assert!(
                framed.len().is_power_of_two(),
                "frame size {} is not a power of 2 for payload size {size}",
                framed.len()
            );
            assert!(framed.len() >= HEADER_LEN + size, "frame too small for payload size {size}");
        }
    }

    // -----------------------------------------------------------------------
    // T-9: HttpSizes targets are correct
    // -----------------------------------------------------------------------

    #[test]
    fn http_sizes_targets_correct() {
        let morpher = TrafficMorpher::new(PaddingStrategy::HttpSizes);

        // Small payload (header + payload = 7) → should round up to 128
        let framed = morpher.pad(SMALL_PAYLOAD).expect("pad");
        assert_eq!(framed.len(), HTTP_TARGET_SIZES[0]);

        // Payload that fits in 256 but not 128 (header = 2, so 127 bytes payload)
        let payload = vec![0xBB; HTTP_TARGET_SIZES[0] - HEADER_LEN + 1]; // 127 bytes
        let framed = morpher.pad(&payload).expect("pad");
        assert_eq!(framed.len(), HTTP_TARGET_SIZES[1]);

        // Payload that exceeds all targets
        let payload = vec![0xCC; HTTP_TARGET_SIZES[4]]; // 1460 bytes payload → unpadded = 1462
        let framed = morpher.pad(&payload).expect("pad");
        assert_eq!(framed.len(), HEADER_LEN + payload.len(), "oversized payload should not be padded");
    }

    // -----------------------------------------------------------------------
    // T-10: FixedMtu with oversized payload falls back gracefully
    // -----------------------------------------------------------------------

    #[test]
    fn fixed_mtu_oversized_fallback() {
        let small_mtu: u16 = 64;
        let morpher = TrafficMorpher::new(PaddingStrategy::FixedMtu(small_mtu));

        // Payload that exceeds the MTU
        let payload = vec![0xDD; usize::from(small_mtu)]; // header + payload > mtu
        let framed = morpher.pad(&payload).expect("pad");
        let recovered = TrafficMorpher::unpad(&framed).expect("unpad");
        assert_eq!(recovered, payload);
        assert_eq!(
            framed.len(),
            HEADER_LEN + payload.len(),
            "oversized payload should not be padded to MTU"
        );
    }

    // -----------------------------------------------------------------------
    // T-11: compute_jitter returns duration within bounds
    // -----------------------------------------------------------------------

    #[test]
    fn jitter_within_bounds() {
        for _ in 0..JITTER_SAMPLE_COUNT {
            let jitter = compute_jitter(JITTER_MAX_MS);
            assert!(
                jitter < Duration::from_millis(JITTER_MAX_MS),
                "jitter {jitter:?} should be < {JITTER_MAX_MS}ms"
            );
        }
    }

    #[test]
    fn jitter_zero_max_returns_zero() {
        let jitter = compute_jitter(0);
        assert_eq!(jitter, Duration::ZERO);
    }

    // -----------------------------------------------------------------------
    // T-12: PaddingStrategy Display/FromStr round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn strategy_display_fromstr_round_trip() {
        let strategies = [
            PaddingStrategy::PowerOfTwo,
            PaddingStrategy::HttpSizes,
            PaddingStrategy::FixedMtu(FIXED_MTU_VALUE),
            PaddingStrategy::None,
        ];
        for strategy in strategies {
            let name = strategy.to_string();
            let parsed: PaddingStrategy = name.parse().expect("parse should succeed");
            assert_eq!(parsed, strategy, "round-trip failed for {strategy}");
        }
    }

    #[test]
    fn strategy_fromstr_case_insensitive() {
        assert_eq!("Power-Of-Two".parse::<PaddingStrategy>().unwrap(), PaddingStrategy::PowerOfTwo);
        assert_eq!("HTTP-SIZES".parse::<PaddingStrategy>().unwrap(), PaddingStrategy::HttpSizes);
        assert_eq!("NONE".parse::<PaddingStrategy>().unwrap(), PaddingStrategy::None);
        assert_eq!(
            "Fixed-Mtu:1500".parse::<PaddingStrategy>().unwrap(),
            PaddingStrategy::FixedMtu(FIXED_MTU_VALUE)
        );
    }

    #[test]
    fn strategy_fromstr_unknown_rejected() {
        let result = "invalid-strategy".parse::<PaddingStrategy>();
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // T-13: Unpad rejects truncated frame (< 2 bytes)
    // -----------------------------------------------------------------------

    #[test]
    fn unpad_rejects_truncated_frame() {
        let result = unpad(&[]);
        assert!(matches!(result, Err(MorphError::FrameTooShort { actual: 0 })));

        let result = unpad(&[0x00]);
        assert!(matches!(result, Err(MorphError::FrameTooShort { actual: 1 })));
    }

    // -----------------------------------------------------------------------
    // T-14: Unpad rejects frame where payload length exceeds remaining bytes
    // -----------------------------------------------------------------------

    #[test]
    fn unpad_rejects_payload_length_overflow() {
        // Header says 100 bytes, but frame only has 5 bytes after header
        let frame = [0x00, 0x64, 0x01, 0x02, 0x03, 0x04, 0x05];
        let result = unpad(&frame);
        assert!(matches!(
            result,
            Err(MorphError::PayloadLengthExceedsFrame {
                payload_len: 100,
                available: 5,
            })
        ));
    }

    // -----------------------------------------------------------------------
    // T-15: Large payload (max u16) pad/unpad round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn max_payload_round_trip() {
        let morpher = TrafficMorpher::new(PaddingStrategy::None);
        let payload = vec![0xEE; MAX_PAYLOAD_LEN];
        let framed = morpher.pad(&payload).expect("pad");
        let recovered = TrafficMorpher::unpad(&framed).expect("unpad");
        assert_eq!(recovered.len(), MAX_PAYLOAD_LEN);
        assert_eq!(recovered, payload);
    }

    #[test]
    fn payload_too_large_rejected() {
        let morpher = TrafficMorpher::new(PaddingStrategy::None);
        let payload = vec![0xFF; MAX_PAYLOAD_LEN + 1];
        let result = morpher.pad(&payload);
        assert!(matches!(result, Err(MorphError::PayloadTooLarge { .. })));
    }

    // -----------------------------------------------------------------------
    // T-16: Integration: pad → encrypt → decrypt → unpad round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn pad_encrypt_decrypt_unpad_round_trip() {
        use crate::crypto::aead::KEY_LEN;
        use crate::transport::encrypted_channel::EncryptedChannel;

        let tx_key = [0x01u8; KEY_LEN];
        let rx_key = [0x02u8; KEY_LEN];

        let morpher = TrafficMorpher::new(PaddingStrategy::PowerOfTwo);
        let mut sender = EncryptedChannel::new(tx_key, rx_key);
        let mut receiver = EncryptedChannel::new(rx_key, tx_key);

        let original = b"integration test payload";

        // Pad → encrypt
        let padded = morpher.pad(original).expect("pad");
        let encrypted = sender.send(&padded).expect("encrypt");

        // Decrypt → unpad
        let decrypted = receiver.recv(&encrypted).expect("decrypt");
        let recovered = TrafficMorpher::unpad(&decrypted).expect("unpad");

        assert_eq!(recovered, original);
    }

    // -----------------------------------------------------------------------
    // T-17: MorphConfig default values
    // -----------------------------------------------------------------------

    #[test]
    fn morph_config_defaults() {
        let config = MorphConfig::default_config();
        assert_eq!(config.strategy, PaddingStrategy::PowerOfTwo);
        assert_eq!(config.max_jitter_ms, DEFAULT_MAX_JITTER_MS);
    }

    // -----------------------------------------------------------------------
    // T-18: Morpher strategy accessor
    // -----------------------------------------------------------------------

    #[test]
    fn morpher_strategy_accessor() {
        let morpher = TrafficMorpher::new(PaddingStrategy::HttpSizes);
        assert_eq!(morpher.strategy(), PaddingStrategy::HttpSizes);
    }
}
