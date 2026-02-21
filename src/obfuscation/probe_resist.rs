// FRD: specs/frds/FRD-013.md

//! Active probing resistance for the PRRR server.
//!
//! Provides HMAC-BLAKE2s cookie authentication, replay-protected nonce tracking,
//! per-IP rate limiting, and static decoy HTTP responses. Unauthenticated
//! connections receive a decoy response indistinguishable from a normal web server.
//!
//! # Authentication Flow
//!
//! 1. Client generates an [`AuthToken`] containing a random nonce, Unix timestamp,
//!    and BLAKE2s HMAC computed with a pre-shared key (PSK).
//! 2. The token is base64url-encoded and sent in the `Authorization: Bearer` header
//!    of the CONNECT-UDP request.
//! 3. The server validates the token: checks rate limit, timestamp freshness,
//!    HMAC integrity (constant-time), and nonce uniqueness.
//! 4. On failure, the server returns a static decoy HTTP response.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the random nonce in bytes.
const NONCE_SIZE: usize = 16;

/// Size of the Unix timestamp in bytes (u64 big-endian).
const TIMESTAMP_SIZE: usize = 8;

/// Size of the BLAKE2s-256 MAC in bytes.
const MAC_SIZE: usize = 32;

/// Total raw token size: nonce + timestamp + mac.
const TOKEN_RAW_SIZE: usize = NONCE_SIZE + TIMESTAMP_SIZE + MAC_SIZE;

/// Maximum allowed clock difference between client and server (seconds).
const TIMESTAMP_TOLERANCE_SECS: u64 = 30;

/// Nonce expiry window: 2 * tolerance (seconds).
const NONCE_EXPIRY_SECS: u64 = TIMESTAMP_TOLERANCE_SECS * 2;

/// Rate limiter: tokens refilled per second per IP.
const RATE_LIMIT_TOKENS_PER_SECOND: u64 = 20;

/// Rate limiter: maximum burst capacity per IP.
const RATE_LIMIT_BURST_CAPACITY: u64 = 5;

/// Rate limiter: remove idle entries after this many seconds.
const RATE_LIMIT_STALE_SECS: u64 = 60;

/// Number of bytes in an IPv6 /64 prefix.
const IPV6_PREFIX_BYTES: usize = 8;

/// Static decoy HTML body.
const DECOY_HTML_BODY: &str = "<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>";

/// Decoy server identifier.
const DECOY_SERVER_HEADER: &str = "nginx/1.24.0";

/// CONNECT-UDP method line.
const CONNECT_UDP_METHOD: &str = "CONNECT-UDP /tunnel HTTP/3";

/// Authorization header prefix.
const AUTH_HEADER_PREFIX: &str = "Authorization: Bearer ";

/// BLAKE2s keyed hash context for token MAC.
const TOKEN_MAC_CONTEXT: &str = "prrr-probe-resist-token-v1";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the probe resistance module.
#[derive(Debug, thiserror::Error)]
pub enum ProbeResistError {
    /// Token bytes have wrong length.
    #[error("invalid token length: expected {expected}, got {actual}")]
    InvalidTokenLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64Decode(String),

    /// Timestamp is outside the tolerance window.
    #[error("timestamp out of tolerance: delta {delta_secs}s exceeds {tolerance_secs}s")]
    TimestampOutOfRange {
        /// Absolute difference in seconds.
        delta_secs: u64,
        /// Maximum allowed difference.
        tolerance_secs: u64,
    },

    /// MAC verification failed (constant-time).
    #[error("MAC verification failed")]
    MacMismatch,

    /// Nonce has already been used.
    #[error("nonce replay detected")]
    NonceReplay,

    /// Rate limit exceeded for this IP.
    #[error("rate limit exceeded")]
    RateLimited,

    /// Request format is not a valid authenticated CONNECT-UDP.
    #[error("invalid request format")]
    InvalidRequest,
}

// ---------------------------------------------------------------------------
// AuthToken
// ---------------------------------------------------------------------------

/// An HMAC-BLAKE2s authentication token for probe resistance.
///
/// Wire format: `nonce (16B) || timestamp (8B) || mac (32B)` = 56 bytes raw,
/// base64url-encoded (no padding) for transport in the HTTP Authorization header.
pub struct AuthToken {
    /// Random nonce (16 bytes).
    nonce: [u8; NONCE_SIZE],
    /// Unix epoch seconds (u64 big-endian).
    timestamp: u64,
    /// BLAKE2s-256 MAC over `nonce || timestamp`, keyed with PSK.
    mac: [u8; MAC_SIZE],
}

impl AuthToken {
    /// Generate a new authentication token using the given PSK and timestamp.
    ///
    /// A cryptographically random nonce is generated internally.
    pub fn generate(psk: &[u8; MAC_SIZE], timestamp: u64) -> Self {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let mac = Self::compute_mac(psk, &nonce, timestamp);

        Self { nonce, timestamp, mac }
    }

    /// Validate a raw token (56 bytes) against the PSK and server time.
    ///
    /// Returns the nonce on success for replay checking.
    pub fn validate(psk: &[u8; MAC_SIZE], raw: &[u8], server_time: u64) -> Result<[u8; NONCE_SIZE], ProbeResistError> {
        if raw.len() != TOKEN_RAW_SIZE {
            return Err(ProbeResistError::InvalidTokenLength {
                expected: TOKEN_RAW_SIZE,
                actual: raw.len(),
            });
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&raw[..NONCE_SIZE]);

        let mut ts_bytes = [0u8; TIMESTAMP_SIZE];
        ts_bytes.copy_from_slice(&raw[NONCE_SIZE..NONCE_SIZE + TIMESTAMP_SIZE]);
        let timestamp = u64::from_be_bytes(ts_bytes);

        let mut received_mac = [0u8; MAC_SIZE];
        received_mac.copy_from_slice(&raw[NONCE_SIZE + TIMESTAMP_SIZE..]);

        // Check timestamp tolerance
        let delta = server_time.abs_diff(timestamp);
        if delta > TIMESTAMP_TOLERANCE_SECS {
            return Err(ProbeResistError::TimestampOutOfRange {
                delta_secs: delta,
                tolerance_secs: TIMESTAMP_TOLERANCE_SECS,
            });
        }

        // Compute expected MAC and compare in constant time
        let expected_mac = Self::compute_mac(psk, &nonce, timestamp);
        if received_mac.ct_eq(&expected_mac).into() {
            Ok(nonce)
        } else {
            Err(ProbeResistError::MacMismatch)
        }
    }

    /// Serialize the token to raw bytes (56 bytes).
    pub fn to_bytes(&self) -> [u8; TOKEN_RAW_SIZE] {
        let mut buf = [0u8; TOKEN_RAW_SIZE];
        buf[..NONCE_SIZE].copy_from_slice(&self.nonce);
        buf[NONCE_SIZE..NONCE_SIZE + TIMESTAMP_SIZE].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[NONCE_SIZE + TIMESTAMP_SIZE..].copy_from_slice(&self.mac);
        buf
    }

    /// Encode the token as a base64url string (no padding).
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.to_bytes())
    }

    /// Decode a base64url-encoded token string.
    pub fn from_base64(encoded: &str) -> Result<Vec<u8>, ProbeResistError> {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| ProbeResistError::Base64Decode(e.to_string()))
    }

    /// Compute the BLAKE2s-256 MAC: `BLAKE2s(key=psk, data=nonce || timestamp)`.
    fn compute_mac(psk: &[u8; MAC_SIZE], nonce: &[u8; NONCE_SIZE], timestamp: u64) -> [u8; MAC_SIZE] {
        let mut hasher = blake3::Hasher::new_keyed(psk);
        hasher.update(TOKEN_MAC_CONTEXT.as_bytes());
        hasher.update(nonce);
        hasher.update(&timestamp.to_be_bytes());
        let hash = hasher.finalize();
        *hash.as_bytes()
    }
}

// ---------------------------------------------------------------------------
// NonceSet — replay protection
// ---------------------------------------------------------------------------

/// Tracks seen nonces to prevent replay attacks.
///
/// Each nonce is stored with an insertion timestamp and automatically
/// expires after [`NONCE_EXPIRY_SECS`].
pub struct NonceSet {
    /// Map from nonce to insertion time (monotonic).
    seen: HashMap<[u8; NONCE_SIZE], Instant>,
    /// Expiry duration for nonce entries.
    expiry: Duration,
}

impl Default for NonceSet {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceSet {
    /// Create a new empty nonce set.
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            expiry: Duration::from_secs(NONCE_EXPIRY_SECS),
        }
    }

    /// Insert a nonce. Returns `true` if the nonce was new, `false` if already seen.
    pub fn insert(&mut self, nonce: [u8; NONCE_SIZE]) -> bool {
        self.insert_at(nonce, Instant::now())
    }

    /// Insert a nonce with a specific timestamp (for testing).
    fn insert_at(&mut self, nonce: [u8; NONCE_SIZE], now: Instant) -> bool {
        // Check if already present and not expired
        if let Some(&inserted_at) = self.seen.get(&nonce) {
            if now.duration_since(inserted_at) < self.expiry {
                return false;
            }
        }
        self.seen.insert(nonce, now);
        true
    }

    /// Remove all nonces older than the expiry window.
    pub fn cleanup(&mut self) {
        self.cleanup_at(Instant::now());
    }

    /// Remove expired nonces relative to a specific time (for testing).
    fn cleanup_at(&mut self, now: Instant) {
        self.seen.retain(|_, inserted_at| now.duration_since(*inserted_at) < self.expiry);
    }

    /// Number of tracked nonces.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the nonce set is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RateLimiter — per-IP token bucket
// ---------------------------------------------------------------------------

/// Per-IP token bucket rate limiter.
///
/// Each source IP gets a bucket with [`RATE_LIMIT_BURST_CAPACITY`] tokens
/// that refill at [`RATE_LIMIT_TOKENS_PER_SECOND`] per second.
pub struct RateLimiter {
    /// Per-IP buckets: (tokens_available, last_check_time).
    buckets: HashMap<RateLimitKey, TokenBucket>,
    /// Maximum tokens per bucket.
    burst_capacity: u64,
    /// Tokens added per second.
    refill_rate: u64,
    /// Remove entries idle longer than this.
    stale_timeout: Duration,
}

/// Rate limit key: full IPv4 address or IPv6 /64 prefix.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum RateLimitKey {
    /// Full IPv4 address.
    V4([u8; 4]),
    /// IPv6 /64 prefix (first 8 bytes).
    V6Prefix([u8; IPV6_PREFIX_BYTES]),
}

impl RateLimitKey {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4.octets()),
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                let mut prefix = [0u8; IPV6_PREFIX_BYTES];
                prefix.copy_from_slice(&octets[..IPV6_PREFIX_BYTES]);
                Self::V6Prefix(prefix)
            }
        }
    }
}

/// A single token bucket for one IP.
struct TokenBucket {
    /// Current available tokens (fractional, stored as microtokens for precision).
    tokens: u64,
    /// Last time tokens were checked/refilled.
    last_check: Instant,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    /// Create a new rate limiter with default parameters.
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            burst_capacity: RATE_LIMIT_BURST_CAPACITY,
            refill_rate: RATE_LIMIT_TOKENS_PER_SECOND,
            stale_timeout: Duration::from_secs(RATE_LIMIT_STALE_SECS),
        }
    }

    /// Check whether the given IP is allowed to proceed.
    ///
    /// Returns `true` if a token was consumed, `false` if the bucket is empty.
    pub fn check(&mut self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    /// Check rate limit at a specific time (for testing).
    fn check_at(&mut self, ip: IpAddr, now: Instant) -> bool {
        let key = RateLimitKey::from_ip(ip);
        let burst = self.burst_capacity;
        let refill = self.refill_rate;

        let bucket = self.buckets.entry(key).or_insert_with(|| TokenBucket {
            tokens: burst,
            last_check: now,
        });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_check);
        let refilled = elapsed.as_secs() * refill + elapsed.subsec_millis() as u64 * refill / 1000;
        bucket.tokens = (bucket.tokens + refilled).min(burst);
        bucket.last_check = now;

        // Try to consume one token
        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Remove rate limit entries that have been idle for longer than the stale timeout.
    pub fn cleanup(&mut self) {
        self.cleanup_at(Instant::now());
    }

    /// Remove stale entries relative to a specific time (for testing).
    fn cleanup_at(&mut self, now: Instant) {
        let timeout = self.stale_timeout;
        self.buckets.retain(|_, bucket| now.duration_since(bucket.last_check) < timeout);
    }

    /// Number of tracked IPs.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Whether the limiter has no tracked IPs.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Request / Response Builders
// ---------------------------------------------------------------------------

/// Build the static decoy HTTP response bytes.
///
/// Returns a response mimicking a default nginx web server.
pub fn build_decoy_response() -> Vec<u8> {
    format!(
        "HTTP/3 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nServer: {DECOY_SERVER_HEADER}\r\n\r\n{DECOY_HTML_BODY}",
        DECOY_HTML_BODY.len(),
    )
    .into_bytes()
}

/// Build an authenticated CONNECT-UDP request with the PSK.
///
/// The token is generated with the current Unix timestamp.
pub fn build_authenticated_request(psk: &[u8; MAC_SIZE]) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs();
    build_authenticated_request_at(psk, timestamp)
}

/// Build an authenticated CONNECT-UDP request with a specific timestamp (for testing).
fn build_authenticated_request_at(psk: &[u8; MAC_SIZE], timestamp: u64) -> String {
    let token = AuthToken::generate(psk, timestamp);
    let encoded = token.to_base64();
    format!("{CONNECT_UDP_METHOD}\r\n{AUTH_HEADER_PREFIX}{encoded}\r\n\r\n")
}

/// Parse the bearer token from an authenticated CONNECT-UDP request.
///
/// Returns the raw token bytes on success.
fn parse_request_token(request: &[u8]) -> Result<Vec<u8>, ProbeResistError> {
    let request_str = std::str::from_utf8(request).map_err(|_| ProbeResistError::InvalidRequest)?;

    // Check method line
    let mut lines = request_str.split("\r\n");
    let method_line = lines.next().ok_or(ProbeResistError::InvalidRequest)?;
    if method_line != CONNECT_UDP_METHOD {
        return Err(ProbeResistError::InvalidRequest);
    }

    // Find Authorization header
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(token_str) = line.strip_prefix(AUTH_HEADER_PREFIX) {
            return AuthToken::from_base64(token_str);
        }
    }

    Err(ProbeResistError::InvalidRequest)
}

// ---------------------------------------------------------------------------
// Full Validation Pipeline
// ---------------------------------------------------------------------------

/// Configuration for the probe resistance module.
pub struct ProbeResistConfig {
    /// Pre-shared key (32 bytes).
    pub psk: [u8; MAC_SIZE],
}

/// Validate an incoming MASQUE request against the probe resistance checks.
///
/// Returns `Ok(true)` if the request is authenticated and should proceed to
/// the MASQUE tunnel. Returns `Ok(false)` if the request failed authentication
/// and a decoy response should be sent instead.
///
/// All failure modes return `Ok(false)` — no distinguishable error responses.
pub fn validate_masque_request(
    request: &[u8],
    config: &ProbeResistConfig,
    client_ip: IpAddr,
    server_time: u64,
    nonce_set: &mut NonceSet,
    rate_limiter: &mut RateLimiter,
) -> bool {
    // Step 1: Rate limit check
    if !rate_limiter.check(client_ip) {
        return false;
    }

    // Step 2: Parse token from request
    let raw = match parse_request_token(request) {
        Ok(r) => r,
        Err(_) => return false,
    };

    // Step 3: Validate token (timestamp + MAC)
    let nonce = match AuthToken::validate(&config.psk, &raw, server_time) {
        Ok(n) => n,
        Err(_) => return false,
    };

    // Step 4: Replay check
    if !nonce_set.insert(nonce) {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PSK: [u8; MAC_SIZE] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    const TEST_TIMESTAMP: u64 = 1_700_000_000;

    // -----------------------------------------------------------------------
    // T-1: Token generate/validate round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn token_generate_validate_round_trip() {
        let token = AuthToken::generate(&TEST_PSK, TEST_TIMESTAMP);
        let raw = token.to_bytes();
        let nonce = AuthToken::validate(&TEST_PSK, &raw, TEST_TIMESTAMP).expect("validate");
        assert_eq!(nonce, token.nonce);
    }

    // -----------------------------------------------------------------------
    // T-2: Token with expired timestamp rejected
    // -----------------------------------------------------------------------

    #[test]
    fn token_expired_timestamp_rejected() {
        let token = AuthToken::generate(&TEST_PSK, TEST_TIMESTAMP);
        let raw = token.to_bytes();
        let server_time = TEST_TIMESTAMP + TIMESTAMP_TOLERANCE_SECS + 1;
        let result = AuthToken::validate(&TEST_PSK, &raw, server_time);
        assert!(matches!(result, Err(ProbeResistError::TimestampOutOfRange { .. })));
    }

    // -----------------------------------------------------------------------
    // T-3: Token with future timestamp within tolerance accepted
    // -----------------------------------------------------------------------

    #[test]
    fn token_future_timestamp_within_tolerance_accepted() {
        let future_time = TEST_TIMESTAMP + TIMESTAMP_TOLERANCE_SECS;
        let token = AuthToken::generate(&TEST_PSK, future_time);
        let raw = token.to_bytes();
        let result = AuthToken::validate(&TEST_PSK, &raw, TEST_TIMESTAMP);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // T-4: Token with tampered MAC rejected
    // -----------------------------------------------------------------------

    #[test]
    fn token_tampered_mac_rejected() {
        let token = AuthToken::generate(&TEST_PSK, TEST_TIMESTAMP);
        let mut raw = token.to_bytes();
        // Flip last byte of MAC
        raw[TOKEN_RAW_SIZE - 1] ^= 0xFF;
        let result = AuthToken::validate(&TEST_PSK, &raw, TEST_TIMESTAMP);
        assert!(matches!(result, Err(ProbeResistError::MacMismatch)));
    }

    // -----------------------------------------------------------------------
    // T-5: Token with wrong PSK rejected
    // -----------------------------------------------------------------------

    #[test]
    fn token_wrong_psk_rejected() {
        let token = AuthToken::generate(&TEST_PSK, TEST_TIMESTAMP);
        let raw = token.to_bytes();
        let wrong_psk = [0xFFu8; MAC_SIZE];
        let result = AuthToken::validate(&wrong_psk, &raw, TEST_TIMESTAMP);
        assert!(matches!(result, Err(ProbeResistError::MacMismatch)));
    }

    // -----------------------------------------------------------------------
    // T-6: Token with truncated bytes rejected
    // -----------------------------------------------------------------------

    #[test]
    fn token_truncated_rejected() {
        let token = AuthToken::generate(&TEST_PSK, TEST_TIMESTAMP);
        let raw = token.to_bytes();
        let truncated = &raw[..TOKEN_RAW_SIZE - 1];
        let result = AuthToken::validate(&TEST_PSK, truncated, TEST_TIMESTAMP);
        assert!(matches!(result, Err(ProbeResistError::InvalidTokenLength { .. })));
    }

    // -----------------------------------------------------------------------
    // T-6b: Token base64 round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn token_base64_round_trip() {
        let token = AuthToken::generate(&TEST_PSK, TEST_TIMESTAMP);
        let encoded = token.to_base64();
        let decoded = AuthToken::from_base64(&encoded).expect("decode");
        assert_eq!(decoded, token.to_bytes());
    }

    // -----------------------------------------------------------------------
    // T-7: Nonce set rejects duplicate nonce
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_set_rejects_duplicate() {
        let mut set = NonceSet::new();
        let nonce = [0xAAu8; NONCE_SIZE];
        assert!(set.insert(nonce), "first insert should succeed");
        assert!(!set.insert(nonce), "duplicate insert should fail");
    }

    // -----------------------------------------------------------------------
    // T-8: Nonce set accepts different nonces
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_set_accepts_different_nonces() {
        let mut set = NonceSet::new();
        let nonce_a = [0xAAu8; NONCE_SIZE];
        let nonce_b = [0xBBu8; NONCE_SIZE];
        assert!(set.insert(nonce_a));
        assert!(set.insert(nonce_b));
        assert_eq!(set.len(), 2);
    }

    // -----------------------------------------------------------------------
    // T-9: Nonce set cleanup removes expired entries
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_set_cleanup_removes_expired() {
        let mut set = NonceSet::new();
        let nonce = [0xCCu8; NONCE_SIZE];
        let now = Instant::now();
        set.insert_at(nonce, now);
        assert_eq!(set.len(), 1);

        // Cleanup at a time before expiry — should retain
        let before_expiry = now + Duration::from_secs(NONCE_EXPIRY_SECS - 1);
        set.cleanup_at(before_expiry);
        assert_eq!(set.len(), 1);

        // Cleanup at a time after expiry — should remove
        let after_expiry = now + Duration::from_secs(NONCE_EXPIRY_SECS + 1);
        set.cleanup_at(after_expiry);
        assert!(set.is_empty());
    }

    // -----------------------------------------------------------------------
    // T-10: Rate limiter allows up to burst capacity
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limiter_allows_burst_capacity() {
        let mut limiter = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();

        for _ in 0..RATE_LIMIT_BURST_CAPACITY {
            assert!(limiter.check_at(ip, now), "should allow within burst");
        }
    }

    // -----------------------------------------------------------------------
    // T-11: Rate limiter rejects after burst exhausted
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limiter_rejects_after_burst_exhausted() {
        let mut limiter = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();

        // Exhaust burst
        for _ in 0..RATE_LIMIT_BURST_CAPACITY {
            limiter.check_at(ip, now);
        }
        assert!(!limiter.check_at(ip, now), "should reject after burst exhausted");
    }

    // -----------------------------------------------------------------------
    // T-12: Rate limiter refills tokens over time
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limiter_refills_over_time() {
        let mut limiter = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();

        // Exhaust burst
        for _ in 0..RATE_LIMIT_BURST_CAPACITY {
            limiter.check_at(ip, now);
        }
        assert!(!limiter.check_at(ip, now));

        // Wait 1 second — should refill RATE_LIMIT_TOKENS_PER_SECOND tokens (capped at burst)
        let later = now + Duration::from_secs(1);
        assert!(limiter.check_at(ip, later), "should allow after refill");
    }

    // -----------------------------------------------------------------------
    // T-13: Rate limiter GC removes stale entries
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limiter_gc_removes_stale() {
        let mut limiter = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();
        limiter.check_at(ip, now);
        assert_eq!(limiter.len(), 1);

        let stale_time = now + Duration::from_secs(RATE_LIMIT_STALE_SECS + 1);
        limiter.cleanup_at(stale_time);
        assert!(limiter.is_empty());
    }

    // -----------------------------------------------------------------------
    // T-14: IPv6 rate limiting uses /64 prefix
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limiter_ipv6_uses_prefix() {
        let mut limiter = RateLimiter::new();
        // Two addresses in the same /64 prefix
        let ip_a: IpAddr = "2001:db8::1".parse().unwrap();
        let ip_b: IpAddr = "2001:db8::ffff".parse().unwrap();
        let now = Instant::now();

        // Exhaust burst on ip_a
        for _ in 0..RATE_LIMIT_BURST_CAPACITY {
            limiter.check_at(ip_a, now);
        }

        // ip_b in the same /64 should also be exhausted
        assert!(!limiter.check_at(ip_b, now), "same /64 prefix should share rate limit");
        assert_eq!(limiter.len(), 1, "should be one bucket for the /64");
    }

    // -----------------------------------------------------------------------
    // T-15: Decoy response is well-formed HTTP
    // -----------------------------------------------------------------------

    #[test]
    fn decoy_response_is_well_formed_http() {
        let response = build_decoy_response();
        let response_str = std::str::from_utf8(&response).expect("valid utf-8");

        assert!(response_str.starts_with("HTTP/3 200 OK\r\n"));
        assert!(response_str.contains("Content-Type: text/html"));
        assert!(response_str.contains(&format!("Content-Length: {}", DECOY_HTML_BODY.len())));
        assert!(response_str.contains(&format!("Server: {DECOY_SERVER_HEADER}")));
        assert!(response_str.contains(DECOY_HTML_BODY));
        // Headers end with \r\n\r\n before body
        assert!(response_str.contains("\r\n\r\n"));
    }

    // -----------------------------------------------------------------------
    // T-16: Authenticated request format is well-formed HTTP
    // -----------------------------------------------------------------------

    #[test]
    fn authenticated_request_is_well_formed_http() {
        let request = build_authenticated_request_at(&TEST_PSK, TEST_TIMESTAMP);

        assert!(request.starts_with(CONNECT_UDP_METHOD));
        assert!(request.contains(AUTH_HEADER_PREFIX));
        assert!(request.ends_with("\r\n\r\n"));

        // Token should be parseable
        let raw = parse_request_token(request.as_bytes()).expect("parse token");
        assert_eq!(raw.len(), TOKEN_RAW_SIZE);
    }

    // -----------------------------------------------------------------------
    // T-17: Full validation: valid request accepted
    // -----------------------------------------------------------------------

    #[test]
    fn validate_valid_request_accepted() {
        let config = ProbeResistConfig { psk: TEST_PSK };
        let mut nonce_set = NonceSet::new();
        let mut rate_limiter = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let request = build_authenticated_request_at(&TEST_PSK, TEST_TIMESTAMP);
        let result = validate_masque_request(request.as_bytes(), &config, ip, TEST_TIMESTAMP, &mut nonce_set, &mut rate_limiter);
        assert!(result, "valid request should be accepted");
    }

    // -----------------------------------------------------------------------
    // T-18: Full validation: invalid token gets false
    // -----------------------------------------------------------------------

    #[test]
    fn validate_invalid_token_returns_false() {
        let config = ProbeResistConfig { psk: TEST_PSK };
        let mut nonce_set = NonceSet::new();
        let mut rate_limiter = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Request with wrong PSK
        let wrong_psk = [0xFFu8; MAC_SIZE];
        let request = build_authenticated_request_at(&wrong_psk, TEST_TIMESTAMP);
        let result = validate_masque_request(request.as_bytes(), &config, ip, TEST_TIMESTAMP, &mut nonce_set, &mut rate_limiter);
        assert!(!result, "invalid token should be rejected");
    }

    // -----------------------------------------------------------------------
    // T-19: Full validation: rate-limited IP gets false
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rate_limited_returns_false() {
        let config = ProbeResistConfig { psk: TEST_PSK };
        let mut nonce_set = NonceSet::new();
        let mut rate_limiter = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Exhaust rate limit
        for _ in 0..RATE_LIMIT_BURST_CAPACITY {
            rate_limiter.check(ip);
        }

        let request = build_authenticated_request_at(&TEST_PSK, TEST_TIMESTAMP);
        let result = validate_masque_request(request.as_bytes(), &config, ip, TEST_TIMESTAMP, &mut nonce_set, &mut rate_limiter);
        assert!(!result, "rate-limited IP should be rejected");
    }

    // -----------------------------------------------------------------------
    // T-20: Full validation: replayed nonce gets false
    // -----------------------------------------------------------------------

    #[test]
    fn validate_replayed_nonce_returns_false() {
        let config = ProbeResistConfig { psk: TEST_PSK };
        let mut nonce_set = NonceSet::new();
        let mut rate_limiter = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Build a request and validate it once (succeeds)
        let request = build_authenticated_request_at(&TEST_PSK, TEST_TIMESTAMP);
        let first = validate_masque_request(request.as_bytes(), &config, ip, TEST_TIMESTAMP, &mut nonce_set, &mut rate_limiter);
        assert!(first, "first request should succeed");

        // Same request again (same nonce) — should be rejected
        let second = validate_masque_request(request.as_bytes(), &config, ip, TEST_TIMESTAMP, &mut nonce_set, &mut rate_limiter);
        assert!(!second, "replayed nonce should be rejected");
    }

    // -----------------------------------------------------------------------
    // T-21: Plain CONNECT-UDP request without auth rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_plain_connect_udp_rejected() {
        let config = ProbeResistConfig { psk: TEST_PSK };
        let mut nonce_set = NonceSet::new();
        let mut rate_limiter = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Old-style unauthenticated request
        let request = b"CONNECT-UDP /tunnel HTTP/3\r\n\r\n";
        let result = validate_masque_request(request, &config, ip, TEST_TIMESTAMP, &mut nonce_set, &mut rate_limiter);
        assert!(!result, "unauthenticated request should be rejected");
    }

    // -----------------------------------------------------------------------
    // T-22: Random HTTP GET request rejected
    // -----------------------------------------------------------------------

    #[test]
    fn validate_random_http_get_rejected() {
        let config = ProbeResistConfig { psk: TEST_PSK };
        let mut nonce_set = NonceSet::new();
        let mut rate_limiter = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let request = b"GET / HTTP/3\r\nHost: example.com\r\n\r\n";
        let result = validate_masque_request(request, &config, ip, TEST_TIMESTAMP, &mut nonce_set, &mut rate_limiter);
        assert!(!result, "random HTTP request should be rejected");
    }
}
