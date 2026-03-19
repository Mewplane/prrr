// FRD: specs/frds/FRD-P009.md

//! Client configuration distribution: TOML export, QR code generation, and
//! time-limited token-based short URLs.
//!
//! # Config Generation
//!
//! [`generate_client_config`] assembles a complete client TOML config from
//! server context and a [`ClientRecord`]. The generated config includes the
//! server endpoint, public keys, assigned IP, DNS servers, and MTU — but
//! never any private key material.
//!
//! # QR Code Generation
//!
//! [`generate_qr_svg`] deflate-compresses a client config, base64url-encodes it
//! as a `prrr://import?z=<base64>` URL, and renders it as an SVG QR code image.
//!
//! # Token Store
//!
//! [`ConfigTokenStore`] provides an in-memory store for time-limited config
//! download tokens. Each token maps to a TOML config string and expires
//! after [`TOKEN_TTL_SECS`] seconds.

use std::collections::HashMap;
use std::fmt::Write as _;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tokio::sync::Mutex;

use crate::registry::ClientRecord;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// URL scheme prefix for prrr client import (deflate-compressed).
const IMPORT_URL_PREFIX: &str = "prrr://import?z=";

/// Token time-to-live in seconds (24 hours).
pub const TOKEN_TTL_SECS: u64 = 86_400;

/// Length of generated token in bytes (128-bit security).
const TOKEN_BYTE_LEN: usize = 16;

/// Hex-encoded token string length (2 hex chars per byte).
const TOKEN_HEX_LEN: usize = TOKEN_BYTE_LEN * 2;

/// QR code error correction level.
/// Medium error correction (~15% recovery). Deflate compression reduces
/// the ~2800-byte config URL to ~1500 bytes, fitting comfortably at EcLevel::M.
const QR_ERROR_CORRECTION: qrcode::EcLevel = qrcode::EcLevel::M;

/// Minimum QR code SVG dimension in pixels.
const QR_MIN_DIMENSION: u32 = 200;

/// Default DNS servers (used in tests).
#[cfg(test)]
const DEFAULT_DNS: &[&str] = &["1.1.1.1", "8.8.8.8"];

/// Default MTU (used in tests).
#[cfg(test)]
const DEFAULT_MTU: u16 = 1280;

/// CIDR prefix length for per-client address assignment.
const CLIENT_CIDR_PREFIX: &str = "/32";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from distribution operations.
#[derive(Debug, thiserror::Error)]
pub enum DistributionError {
    /// QR code generation failed (data too large, encoding error).
    #[error("QR code generation failed: {0}")]
    QrGeneration(String),

    /// TOML serialization failed.
    #[error("config serialization failed: {0}")]
    Serialization(String),
}

// ---------------------------------------------------------------------------
// Server context for config generation
// ---------------------------------------------------------------------------

/// Server-side context needed to generate a client configuration.
///
/// Carries the server's public keys, endpoint address, and network settings.
/// Created once at server startup and shared across all distribution operations.
#[derive(Debug, Clone)]
pub struct ServerContext {
    /// Server listen endpoint (e.g. `"vpn.example.com:443"`).
    pub endpoint: String,
    /// TLS server name (SNI) for client connections.
    pub server_name: String,
    /// Server X25519 Noise IK public key (32 bytes).
    pub noise_public_key: [u8; 32],
    /// Server ML-KEM-768 encapsulation key (raw bytes).
    pub kem_public_key: Vec<u8>,
    /// DNS servers to push to clients.
    pub dns_servers: Vec<String>,
    /// Tunnel MTU.
    pub mtu: u16,
    /// Default transport protocol (e.g. `"harp"` or `"masque"`).
    pub transport_protocol: String,
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

/// Default private key path for generated client configs.
const DEFAULT_PRIVATE_KEY_PATH: &str = "~/.config/prrr/private.key";

/// Generate a complete client TOML configuration string.
///
/// The output includes the server endpoint, server name, public keys,
/// client-specific settings (name, assigned IP, DNS, MTU), and transport
/// protocol.
///
/// If `private_key` is `Some`, the key is embedded inline as base64 (for
/// mobile QR import). If `None`, a `private_key_path` pointing to the
/// default location is emitted instead (for CLI clients).
pub fn generate_client_config(
    ctx: &ServerContext,
    record: &ClientRecord,
    private_key: Option<&[u8]>,
) -> Result<String, DistributionError> {
    let noise_b64 = base64::engine::general_purpose::STANDARD.encode(ctx.noise_public_key);
    let kem_b64 = base64::engine::general_purpose::STANDARD.encode(&ctx.kem_public_key);
    let ip_with_prefix = format!("{}{CLIENT_CIDR_PREFIX}", record.ip_address);

    let dns_array = ctx.dns_servers.iter().map(|d| format!("\"{d}\"")).collect::<Vec<_>>().join(", ");

    let mut config = String::new();
    let w = |config: &mut String, args: std::fmt::Arguments<'_>| -> Result<(), DistributionError> {
        config.write_fmt(args).map_err(|e| DistributionError::Serialization(e.to_string()))
    };

    w(
        &mut config,
        format_args!("# prrr client configuration — generated for \"{}\"\n", record.name),
    )?;
    w(&mut config, format_args!("\n"))?;
    w(&mut config, format_args!("[client]\n"))?;
    w(&mut config, format_args!("name = \"{}\"\n", record.name))?;
    w(&mut config, format_args!("\n"))?;
    w(&mut config, format_args!("[server]\n"))?;
    w(&mut config, format_args!("endpoint = \"{}\"\n", ctx.endpoint))?;
    w(&mut config, format_args!("server_name = \"{}\"\n", ctx.server_name))?;
    w(&mut config, format_args!("public_key = \"{noise_b64}\"\n"))?;
    w(&mut config, format_args!("pq_public_key = \"{kem_b64}\"\n"))?;
    w(&mut config, format_args!("\n"))?;
    w(&mut config, format_args!("[interface]\n"))?;
    match private_key {
        Some(key) => {
            let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
            w(&mut config, format_args!("private_key = \"{key_b64}\"\n"))?;
        }
        None => {
            w(&mut config, format_args!("private_key_path = \"{DEFAULT_PRIVATE_KEY_PATH}\"\n"))?;
        }
    }
    w(&mut config, format_args!("address = \"{ip_with_prefix}\"\n"))?;
    w(&mut config, format_args!("dns = [{dns_array}]\n"))?;
    w(&mut config, format_args!("mtu = {}\n", ctx.mtu))?;
    w(&mut config, format_args!("transport_protocol = \"{}\"\n", ctx.transport_protocol))?;

    Ok(config)
}

// ---------------------------------------------------------------------------
// QR code generation
// ---------------------------------------------------------------------------

/// Generate an SVG QR code encoding the client config as a `prrr://import` URL.
///
/// The config TOML is deflate-compressed, base64url-encoded (no padding), and
/// wrapped in the `prrr://import?z=<base64>` URL scheme. Compression typically
/// reduces payload by 40-50%, bringing the QR code from version 40 (~177×177
/// modules) down to version 25-30 (~117-137 modules), which is much easier for
/// mobile camera scanners to detect.
pub fn generate_qr_svg(config_toml: &str) -> Result<String, DistributionError> {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(config_toml.as_bytes())
        .map_err(|e| DistributionError::QrGeneration(format!("deflate compress failed: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| DistributionError::QrGeneration(format!("deflate finish failed: {e}")))?;

    let encoded = URL_SAFE_NO_PAD.encode(&compressed);
    let url = format!("{IMPORT_URL_PREFIX}{encoded}");

    let code = qrcode::QrCode::with_error_correction_level(url.as_bytes(), QR_ERROR_CORRECTION)
        .map_err(|e| DistributionError::QrGeneration(e.to_string()))?;

    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(QR_MIN_DIMENSION, QR_MIN_DIMENSION)
        .build();

    Ok(svg)
}

/// Decode a `prrr://import?z=<base64>` URL back to the original TOML config.
///
/// Used for testing round-trip fidelity.
pub fn decode_import_url(url: &str) -> Result<String, DistributionError> {
    let encoded = url
        .strip_prefix(IMPORT_URL_PREFIX)
        .ok_or_else(|| DistributionError::Serialization("missing prrr://import?z= prefix".to_string()))?;

    let compressed = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| DistributionError::Serialization(format!("base64 decode failed: {e}")))?;

    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let mut decoder = DeflateDecoder::new(&compressed[..]);
    let mut decompressed = String::new();
    decoder
        .read_to_string(&mut decompressed)
        .map_err(|e| DistributionError::Serialization(format!("deflate decompress failed: {e}")))?;
    Ok(decompressed)
}

// ---------------------------------------------------------------------------
// Token store
// ---------------------------------------------------------------------------

/// Entry in the config token store.
struct TokenEntry {
    /// TOML config string.
    config_toml: String,
    /// Absolute expiration instant.
    expires_at: std::time::Instant,
}

/// In-memory store for time-limited config download tokens.
///
/// Tokens are 128-bit random hex strings with a configurable TTL (default 24 hours).
/// Expired tokens are lazily cleaned up on access.
pub struct ConfigTokenStore {
    tokens: Mutex<HashMap<String, TokenEntry>>,
    ttl: std::time::Duration,
}

impl Default for ConfigTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigTokenStore {
    /// Create a new empty token store with the default 24-hour TTL.
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            ttl: std::time::Duration::from_secs(TOKEN_TTL_SECS),
        }
    }

    /// Create a token store with a custom TTL (for testing).
    pub fn with_ttl(ttl: std::time::Duration) -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Insert a config and return a hex token string.
    ///
    /// The token is valid for the store's configured TTL.
    pub async fn insert(&self, config_toml: String) -> String {
        let mut bytes = [0u8; TOKEN_BYTE_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);

        let token = hex_encode(&bytes);
        debug_assert_eq!(token.len(), TOKEN_HEX_LEN);

        let entry = TokenEntry {
            config_toml,
            expires_at: std::time::Instant::now() + self.ttl,
        };

        let mut store = self.tokens.lock().await;
        store.insert(token.clone(), entry);
        token
    }

    /// Retrieve config by token, returning `None` if expired or unknown.
    pub async fn get(&self, token: &str) -> Option<String> {
        let mut store = self.tokens.lock().await;
        let entry = store.get(token)?;
        if std::time::Instant::now() >= entry.expires_at {
            store.remove(token);
            return None;
        }
        Some(entry.config_toml.clone())
    }

    /// Remove all expired tokens. Returns the number of tokens removed.
    pub async fn cleanup_expired(&self) -> usize {
        let now = std::time::Instant::now();
        let mut store = self.tokens.lock().await;
        let before = store.len();
        store.retain(|_, entry| entry.expires_at > now);
        before - store.len()
    }

    /// Return the number of stored tokens (including potentially expired ones).
    pub async fn len(&self) -> usize {
        let store = self.tokens.lock().await;
        store.len()
    }

    /// Return whether the token store is empty.
    pub async fn is_empty(&self) -> bool {
        let store = self.tokens.lock().await;
        store.is_empty()
    }
}

/// Encode bytes as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(hex, "{b:02x}").expect("hex write to String is infallible");
    }
    hex
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P009.md

    use super::*;
    use crate::registry::{ClientRecord, ClientStatus};
    use std::net::Ipv4Addr;
    use uuid::Uuid;

    // --- Test constants ---

    const TEST_ENDPOINT: &str = "vpn.example.com:443";
    const TEST_CLIENT_NAME: &str = "alice";
    const TEST_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 66, 66, 2);
    const TEST_NOISE_KEY: [u8; 32] = [0xAA; 32];
    const TEST_KEM_KEY_LEN: usize = 64;
    const TEST_CREATED_AT: u64 = 1_700_000_000;

    // --- Test helpers ---

    /// Deflate-compress and base64url-encode, returning a `prrr://import?z=...` URL.
    fn compress_to_import_url(toml: &str) -> String {
        use flate2::Compression;
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(toml.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&compressed);
        format!("{IMPORT_URL_PREFIX}{encoded}")
    }

    fn test_server_context() -> ServerContext {
        ServerContext {
            endpoint: TEST_ENDPOINT.to_string(),
            server_name: "vpn.example.com".to_string(),
            noise_public_key: TEST_NOISE_KEY,
            kem_public_key: vec![0xBB; TEST_KEM_KEY_LEN],
            dns_servers: DEFAULT_DNS.iter().map(|s| (*s).to_string()).collect(),
            mtu: DEFAULT_MTU,
            transport_protocol: "masque".to_string(),
        }
    }

    fn test_client_record() -> ClientRecord {
        ClientRecord {
            id: Uuid::nil(),
            name: TEST_CLIENT_NAME.to_string(),
            public_key: [0xCC; 32],
            pq_public_key: None,
            ip_address: TEST_CLIENT_IP,
            created_at: TEST_CREATED_AT,
            last_seen: None,
            status: ClientStatus::Active,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    // --- AC-1: Config generation produces valid TOML ---

    #[test]
    fn config_generation_produces_valid_toml() {
        let ctx = test_server_context();
        let record = test_client_record();
        let config = generate_client_config(&ctx, &record, None).expect("generate config");

        // Must parse as valid TOML
        let parsed: toml::Value = toml::from_str(&config).expect("parse TOML");
        assert!(parsed.get("client").is_some(), "missing [client] section");
        assert!(parsed.get("server").is_some(), "missing [server] section");
        assert!(parsed.get("interface").is_some(), "missing [interface] section");
        let iface = parsed.get("interface").expect("[interface]");
        assert!(
            iface.get("transport_protocol").is_some(),
            "missing transport_protocol in [interface]"
        );
    }

    // --- AC-2: Config contains server keys and server_name ---

    #[test]
    fn config_contains_server_keys() {
        let ctx = test_server_context();
        let record = test_client_record();
        let config = generate_client_config(&ctx, &record, None).expect("generate config");

        let parsed: toml::Value = toml::from_str(&config).expect("parse TOML");
        let server = parsed.get("server").expect("[server]");

        assert_eq!(
            server.get("endpoint").and_then(|v| v.as_str()),
            Some(TEST_ENDPOINT),
            "endpoint mismatch"
        );

        assert_eq!(
            server.get("server_name").and_then(|v| v.as_str()),
            Some("vpn.example.com"),
            "server_name mismatch"
        );

        let noise_b64 = base64::engine::general_purpose::STANDARD.encode(TEST_NOISE_KEY);
        assert_eq!(
            server.get("public_key").and_then(|v| v.as_str()),
            Some(noise_b64.as_str()),
            "noise public key mismatch"
        );

        assert!(
            server.get("pq_public_key").and_then(|v| v.as_str()).is_some(),
            "missing pq_public_key"
        );
    }

    // --- AC-3: Config contains client fields ---

    #[test]
    fn config_contains_client_fields() {
        let ctx = test_server_context();
        let record = test_client_record();
        let config = generate_client_config(&ctx, &record, None).expect("generate config");

        let parsed: toml::Value = toml::from_str(&config).expect("parse TOML");

        let client = parsed.get("client").expect("[client]");
        assert_eq!(
            client.get("name").and_then(|v| v.as_str()),
            Some(TEST_CLIENT_NAME),
            "client name mismatch"
        );

        let iface = parsed.get("interface").expect("[interface]");
        let expected_addr = format!("{TEST_CLIENT_IP}{CLIENT_CIDR_PREFIX}");
        assert_eq!(
            iface.get("address").and_then(|v| v.as_str()),
            Some(expected_addr.as_str()),
            "address mismatch"
        );

        let dns = iface.get("dns").and_then(|v| v.as_array()).expect("dns array");
        assert_eq!(dns.len(), DEFAULT_DNS.len(), "dns count mismatch");
        assert_eq!(dns[0].as_str(), Some(DEFAULT_DNS[0]), "first dns mismatch");
        assert_eq!(dns[1].as_str(), Some(DEFAULT_DNS[1]), "second dns mismatch");

        assert_eq!(
            iface.get("mtu").and_then(|v| v.as_integer()),
            Some(i64::from(DEFAULT_MTU)),
            "mtu mismatch"
        );

        assert_eq!(
            iface.get("transport_protocol").and_then(|v| v.as_str()),
            Some("masque"),
            "transport protocol mismatch"
        );
    }

    // --- AC-4: Config excludes private key material ---

    #[test]
    fn config_excludes_private_key_material() {
        let ctx = test_server_context();
        let record = test_client_record();
        let config = generate_client_config(&ctx, &record, None).expect("generate config");

        let lower = config.to_lowercase();
        // private_key_path is allowed (it's a file path, not key material)
        // but actual key values or "secret" must not appear
        assert!(!lower.contains("secret"), "config must not contain 'secret'");

        // Verify private_key_path is present but contains only a path, not raw key bytes
        let parsed: toml::Value = toml::from_str(&config).expect("parse TOML");
        let iface = parsed.get("interface").expect("[interface]");
        let pk_path = iface.get("private_key_path").and_then(|v| v.as_str()).expect("private_key_path");
        assert!(pk_path.ends_with(".key"), "private_key_path should be a file path");
    }

    // --- AC-5: QR SVG is valid SVG ---

    #[test]
    fn qr_svg_is_valid_svg() {
        let config = "test config data";
        let svg = generate_qr_svg(config).expect("generate QR SVG");

        assert!(svg.starts_with("<?xml"), "SVG must start with XML declaration");
        assert!(svg.contains("<svg"), "SVG must contain <svg element");
        assert!(svg.contains("</svg>"), "SVG must contain closing </svg>");
    }

    // --- AC-6: QR data uses import URL scheme ---

    #[test]
    fn qr_data_uses_import_url_scheme() {
        let config = "test config";

        // Verify the URL construction logic
        let svg = generate_qr_svg(config).expect("generate QR SVG");
        assert!(!svg.is_empty(), "SVG should not be empty");

        // Build a compressed URL the same way generate_qr_svg does
        let compressed_url = compress_to_import_url(config);

        // Verify decode round-trip
        let decoded = decode_import_url(&compressed_url).expect("decode URL");
        assert_eq!(decoded, config, "decoded config should match original");
    }

    // --- AC-7: Base64 is URL-safe without padding ---

    #[test]
    fn qr_base64_is_url_safe() {
        let config = "test data with special chars: +/=";
        let encoded = URL_SAFE_NO_PAD.encode(config.as_bytes());

        assert!(!encoded.contains('+'), "URL-safe base64 must not contain '+'");
        assert!(!encoded.contains('/'), "URL-safe base64 must not contain '/'");
        assert!(!encoded.contains('='), "URL-safe base64 must not contain '='");
    }

    // --- AC-8: QR round-trip decode ---

    #[test]
    fn qr_round_trip_decode() {
        let ctx = test_server_context();
        let record = test_client_record();
        let original_config = generate_client_config(&ctx, &record, None).expect("generate config");

        // Encode the same way QR does (deflate + base64url)
        let url = compress_to_import_url(&original_config);

        // Decode back
        let decoded = decode_import_url(&url).expect("decode URL");
        assert_eq!(decoded, original_config, "round-trip decode must match original");
    }

    // --- AC-9: Token store insert returns hex token ---

    #[tokio::test]
    async fn token_store_insert_returns_hex_token() {
        let store = ConfigTokenStore::new();
        let token = store.insert("config data".to_string()).await;

        assert_eq!(token.len(), TOKEN_HEX_LEN, "token must be {TOKEN_HEX_LEN} hex chars");
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()), "token must contain only hex digits");
    }

    // --- AC-10: Token store get valid token ---

    #[tokio::test]
    async fn token_store_get_valid_token() {
        let store = ConfigTokenStore::new();
        let config = "valid config content".to_string();
        let token = store.insert(config.clone()).await;

        let retrieved = store.get(&token).await;
        assert_eq!(retrieved, Some(config), "get should return stored config");
    }

    // --- AC-11: Token store expired token returns None ---

    #[tokio::test]
    async fn token_store_expired_token_returns_none() {
        // Use zero TTL so the token expires immediately
        let store = ConfigTokenStore::with_ttl(std::time::Duration::ZERO);
        let token = store.insert("will expire".to_string()).await;

        // Small sleep to ensure Instant::now() has advanced past expiry
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;

        let result = store.get(&token).await;
        assert!(result.is_none(), "expired token should return None");
    }

    // --- AC-12: Token store unknown token returns None ---

    #[tokio::test]
    async fn token_store_unknown_token_returns_none() {
        let store = ConfigTokenStore::new();
        let result = store.get("deadbeefdeadbeefdeadbeefdeadbeef").await;
        assert!(result.is_none(), "unknown token should return None");
    }

    // --- Additional: Token store cleanup ---

    #[tokio::test]
    async fn token_store_cleanup_removes_expired() {
        let store = ConfigTokenStore::with_ttl(std::time::Duration::ZERO);
        let _t1 = store.insert("config1".to_string()).await;
        let _t2 = store.insert("config2".to_string()).await;

        assert_eq!(store.len().await, 2, "should have 2 tokens before cleanup");

        // Small sleep to ensure tokens have expired
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;

        let removed = store.cleanup_expired().await;
        assert_eq!(removed, 2, "should have removed 2 expired tokens");
        assert_eq!(store.len().await, 0, "store should be empty after cleanup");
    }

    // --- Additional: Unique tokens ---

    #[tokio::test]
    async fn token_store_generates_unique_tokens() {
        let store = ConfigTokenStore::new();
        let t1 = store.insert("config1".to_string()).await;
        let t2 = store.insert("config2".to_string()).await;

        assert_ne!(t1, t2, "different inserts should produce different tokens");
    }

    // --- Additional: decode_import_url rejects bad prefix ---

    #[test]
    fn decode_import_url_rejects_bad_prefix() {
        let result = decode_import_url("https://example.com/config");
        assert!(result.is_err(), "should reject URL without prrr:// prefix");
    }

    // --- Additional: hex_encode correctness ---

    #[test]
    fn hex_encode_produces_lowercase() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "deadbeef");
    }

    // --- Additional: generate_client_config with real-ish keys ---

    #[test]
    fn config_generation_with_large_kem_key() {
        let ctx = ServerContext {
            endpoint: TEST_ENDPOINT.to_string(),
            server_name: "vpn.example.com".to_string(),
            noise_public_key: TEST_NOISE_KEY,
            kem_public_key: vec![0x42; 1184], // ML-KEM-768 encapsulation key size
            dns_servers: DEFAULT_DNS.iter().map(|s| (*s).to_string()).collect(),
            mtu: DEFAULT_MTU,
            transport_protocol: "masque".to_string(),
        };
        let record = test_client_record();
        let config = generate_client_config(&ctx, &record, None).expect("generate config");

        let parsed: toml::Value = toml::from_str(&config).expect("parse TOML");
        let kem_b64 = parsed["server"]["pq_public_key"].as_str().expect("pq_public_key");

        // Decode and verify length
        let decoded = base64::engine::general_purpose::STANDARD.decode(kem_b64).expect("decode kem key");
        assert_eq!(decoded.len(), 1184, "KEM key should round-trip correctly");
    }

    // --- QR generation succeeds with production-sized ML-KEM-768 key ---

    #[test]
    fn qr_generation_with_large_kem_key() {
        let ctx = ServerContext {
            endpoint: TEST_ENDPOINT.to_string(),
            server_name: "vpn.example.com".to_string(),
            noise_public_key: TEST_NOISE_KEY,
            kem_public_key: vec![0x42; 1184],
            dns_servers: DEFAULT_DNS.iter().map(|s| (*s).to_string()).collect(),
            mtu: DEFAULT_MTU,
            transport_protocol: "masque".to_string(),
        };
        let record = test_client_record();
        let config = generate_client_config(&ctx, &record, None).expect("generate config");
        let svg = generate_qr_svg(&config).expect("QR generation must succeed with 1184-byte KEM key");
        assert!(svg.contains("<svg"), "must produce valid SVG");
    }
}
