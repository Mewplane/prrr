// FRD: specs/frds/FRD-010.md

//! TLS fingerprint mimicry for censorship evasion.
//!
//! Configures rustls `CryptoProvider` with browser-like cipher suite and
//! key exchange group ordering to avoid the default rustls TLS fingerprint.
//! Includes JA3 fingerprint computation for verification.
//!
//! # Limitations
//!
//! rustls v0.23 randomizes TLS extension ordering internally — there is no
//! public API to control it. Only 3 TLS 1.3 cipher suites are available for
//! QUIC (browsers advertise 15+). Exact browser JA3/JA4 mimicry is therefore
//! impossible with stock rustls. This module provides **approximate** mimicry
//! by reordering the controllable fields (cipher suites and key exchange groups).

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use md5::{Digest, Md5};
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring as ring_provider;

use crate::transport::TransportError;

// ---------------------------------------------------------------------------
// Constants — JA3 fields
// ---------------------------------------------------------------------------

/// TLS 1.2 wire version used in ClientHello even for TLS 1.3 connections.
const JA3_TLS_VERSION: u16 = 771;

/// EC point format: uncompressed (standard for TLS 1.3).
const JA3_EC_POINT_FORMAT_UNCOMPRESSED: u16 = 0;

// ---------------------------------------------------------------------------
// TLS Profile
// ---------------------------------------------------------------------------

/// A TLS fingerprint profile that controls cipher suite and key exchange
/// group ordering in the rustls `CryptoProvider`.
///
/// Each profile reorders the same set of TLS 1.3 cipher suites and key
/// exchange groups to produce a different JA3 fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsProfile {
    /// Chrome-like cipher suite ordering:
    /// `AES_256_GCM`, `CHACHA20_POLY1305`, `AES_128_GCM`.
    Chrome,

    /// Firefox-like cipher suite ordering:
    /// `AES_128_GCM`, `CHACHA20_POLY1305`, `AES_256_GCM`.
    Firefox,

    /// Default rustls ring provider ordering (no customization).
    Default,
}

/// Display name for Chrome profile.
const PROFILE_NAME_CHROME: &str = "chrome";

/// Display name for Firefox profile.
const PROFILE_NAME_FIREFOX: &str = "firefox";

/// Display name for Default profile.
const PROFILE_NAME_DEFAULT: &str = "default";

impl fmt::Display for TlsProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Chrome => PROFILE_NAME_CHROME,
            Self::Firefox => PROFILE_NAME_FIREFOX,
            Self::Default => PROFILE_NAME_DEFAULT,
        };
        f.write_str(name)
    }
}

/// Error returned when parsing an unknown TLS profile name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTlsProfileError {
    /// The unknown profile name that was provided.
    pub unknown: String,
}

impl fmt::Display for ParseTlsProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown TLS profile: '{}'", self.unknown)
    }
}

impl std::error::Error for ParseTlsProfileError {}

impl FromStr for TlsProfile {
    type Err = ParseTlsProfileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            PROFILE_NAME_CHROME => Ok(Self::Chrome),
            PROFILE_NAME_FIREFOX => Ok(Self::Firefox),
            PROFILE_NAME_DEFAULT => Ok(Self::Default),
            _ => Err(ParseTlsProfileError { unknown: s.to_string() }),
        }
    }
}

// ---------------------------------------------------------------------------
// JA3 Components
// ---------------------------------------------------------------------------

/// Raw JA3 fingerprint components for inspection.
///
/// JA3 is computed as `MD5(TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats)`
/// where each section uses comma-separated IANA values and sections are
/// separated by commas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3Components {
    /// TLS version (wire format): 771 for TLS 1.3 ClientHello.
    pub tls_version: u16,

    /// IANA cipher suite identifiers in profile order.
    pub cipher_suites: Vec<u16>,

    /// IANA named group identifiers in profile order.
    pub groups: Vec<u16>,

    /// EC point format values.
    pub ec_point_formats: Vec<u16>,
}

impl Ja3Components {
    /// Build the JA3 raw string (before MD5 hashing).
    ///
    /// Format: `TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats`
    /// Extensions field is empty (not controllable via rustls).
    pub fn to_ja3_string(&self) -> String {
        let ciphers = self.cipher_suites.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-");

        let groups = self.groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-");

        let point_formats = self.ec_point_formats.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("-");

        // Extensions field left empty (rustls randomizes extension ordering)
        format!("{},{},,{},{}", self.tls_version, ciphers, groups, point_formats)
    }
}

// ---------------------------------------------------------------------------
// CryptoProvider builder
// ---------------------------------------------------------------------------

/// Build a `rustls::CryptoProvider` with cipher suite and key exchange group
/// ordering matching the given TLS profile.
///
/// All profiles use the same set of cipher suites and groups from the ring
/// provider — only the ordering differs.
pub fn build_crypto_provider(profile: TlsProfile) -> CryptoProvider {
    let mut provider = ring_provider::default_provider();

    match profile {
        TlsProfile::Chrome => {
            // Chrome-like: AES_256_GCM, CHACHA20_POLY1305, AES_128_GCM
            provider.cipher_suites = vec![
                ring_provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
                ring_provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                ring_provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ];
            provider.kx_groups = vec![
                ring_provider::kx_group::X25519,
                ring_provider::kx_group::SECP256R1,
                ring_provider::kx_group::SECP384R1,
            ];
        }
        TlsProfile::Firefox => {
            // Firefox-like: AES_128_GCM, CHACHA20_POLY1305, AES_256_GCM
            provider.cipher_suites = vec![
                ring_provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
                ring_provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                ring_provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
            ];
            provider.kx_groups = vec![
                ring_provider::kx_group::X25519,
                ring_provider::kx_group::SECP256R1,
                ring_provider::kx_group::SECP384R1,
            ];
        }
        TlsProfile::Default => {
            // Keep default ring provider ordering (TLS 1.3 suites only for QUIC)
            provider.cipher_suites = vec![
                ring_provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
                ring_provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
                ring_provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            ];
            provider.kx_groups = vec![
                ring_provider::kx_group::X25519,
                ring_provider::kx_group::SECP256R1,
                ring_provider::kx_group::SECP384R1,
            ];
        }
    }

    provider
}

/// Extract the JA3 components for a given TLS profile.
///
/// Returns the cipher suite and key exchange group IANA values in profile
/// order, suitable for JA3 fingerprint computation.
pub fn ja3_components(profile: TlsProfile) -> Ja3Components {
    let provider = build_crypto_provider(profile);

    let cipher_suites: Vec<u16> = provider.cipher_suites.iter().map(|cs| u16::from(cs.suite())).collect();

    let groups: Vec<u16> = provider.kx_groups.iter().map(|g| u16::from(g.name())).collect();

    Ja3Components {
        tls_version: JA3_TLS_VERSION,
        cipher_suites,
        groups,
        ec_point_formats: vec![JA3_EC_POINT_FORMAT_UNCOMPRESSED],
    }
}

/// Compute the JA3 fingerprint hash (MD5 hex) for a given TLS profile.
///
/// The hash covers TLS version, cipher suites, key exchange groups, and
/// EC point formats in profile order. The extensions field is empty because
/// rustls randomizes extension ordering internally.
pub fn compute_ja3_hash(profile: TlsProfile) -> String {
    let components = ja3_components(profile);
    let ja3_string = components.to_ja3_string();

    let mut hasher = Md5::new();
    hasher.update(ja3_string.as_bytes());
    let result = hasher.finalize();

    format!("{result:032x}")
}

// ---------------------------------------------------------------------------
// Quinn config builders with TLS profile
// ---------------------------------------------------------------------------

/// Build a `quinn::ClientConfig` with the given TLS profile applied.
///
/// When `insecure` is `true`, skips certificate verification (dev/test).
/// When `insecure` is `false`, verifies against the Mozilla CA root store.
/// ALPN is set to `h3` for MASQUE compatibility.
pub fn build_mimicked_client_config(profile: TlsProfile, insecure: bool) -> Result<quinn::ClientConfig, TransportError> {
    let provider = build_crypto_provider(profile);
    let verifier = crate::transport::tls::build_cert_verifier(insecure);

    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::TlsConfig(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![crate::transport::masque::ALPN_H3.to_vec()];

    let quic_client_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    client_config.transport_config(Arc::new(crate::transport::masque::datagram_transport_config(25, 300)));

    Ok(client_config)
}

/// Build a `quinn::ServerConfig` with the given TLS profile applied.
///
/// Accepts a certificate chain (one or more certs) and a private key.
/// ALPN is set to `h3` for MASQUE compatibility.
pub fn build_mimicked_server_config(
    profile: TlsProfile,
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, TransportError> {
    let provider = build_crypto_provider(profile);

    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::TlsConfig(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    tls_config.alpn_protocols = vec![crate::transport::masque::ALPN_H3.to_vec()];

    let quic_server_config =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).map_err(|e| TransportError::TlsConfig(e.to_string()))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(crate::transport::masque::datagram_transport_config(25, 300)));

    Ok(server_config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // IANA cipher suite identifiers (TLS 1.3)
    const IANA_TLS13_AES_128_GCM_SHA256: u16 = 0x1301;
    const IANA_TLS13_AES_256_GCM_SHA384: u16 = 0x1302;
    const IANA_TLS13_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

    // IANA named group identifiers
    const IANA_X25519: u16 = 0x001d;
    const IANA_SECP256R1: u16 = 0x0017;
    const IANA_SECP384R1: u16 = 0x0018;

    // Test-only constants
    const MD5_HEX_LENGTH: usize = 32;
    const TLS13_CIPHER_SUITE_COUNT: usize = 3;

    // -----------------------------------------------------------------------
    // T-1: Chrome profile produces correct cipher suite ordering
    // -----------------------------------------------------------------------

    #[test]
    fn chrome_profile_cipher_suite_ordering() {
        let provider = build_crypto_provider(TlsProfile::Chrome);
        let suites: Vec<u16> = provider.cipher_suites.iter().map(|cs| u16::from(cs.suite())).collect();

        assert_eq!(
            suites,
            vec![
                IANA_TLS13_AES_256_GCM_SHA384,
                IANA_TLS13_CHACHA20_POLY1305_SHA256,
                IANA_TLS13_AES_128_GCM_SHA256,
            ],
            "Chrome profile should order: AES_256, CHACHA20, AES_128"
        );
    }

    // -----------------------------------------------------------------------
    // T-2: Firefox profile produces correct cipher suite ordering
    // -----------------------------------------------------------------------

    #[test]
    fn firefox_profile_cipher_suite_ordering() {
        let provider = build_crypto_provider(TlsProfile::Firefox);
        let suites: Vec<u16> = provider.cipher_suites.iter().map(|cs| u16::from(cs.suite())).collect();

        assert_eq!(
            suites,
            vec![
                IANA_TLS13_AES_128_GCM_SHA256,
                IANA_TLS13_CHACHA20_POLY1305_SHA256,
                IANA_TLS13_AES_256_GCM_SHA384,
            ],
            "Firefox profile should order: AES_128, CHACHA20, AES_256"
        );
    }

    // -----------------------------------------------------------------------
    // T-3: Default profile produces standard rustls ordering
    // -----------------------------------------------------------------------

    #[test]
    fn default_profile_cipher_suite_ordering() {
        let provider = build_crypto_provider(TlsProfile::Default);
        let suites: Vec<u16> = provider.cipher_suites.iter().map(|cs| u16::from(cs.suite())).collect();

        assert_eq!(
            suites,
            vec![
                IANA_TLS13_AES_256_GCM_SHA384,
                IANA_TLS13_AES_128_GCM_SHA256,
                IANA_TLS13_CHACHA20_POLY1305_SHA256,
            ],
            "Default profile should use standard rustls ordering"
        );
    }

    // -----------------------------------------------------------------------
    // T-4: Chrome and Firefox profiles produce different JA3 hashes
    // -----------------------------------------------------------------------

    #[test]
    fn chrome_and_firefox_produce_different_ja3() {
        let chrome_hash = compute_ja3_hash(TlsProfile::Chrome);
        let firefox_hash = compute_ja3_hash(TlsProfile::Firefox);

        assert_ne!(
            chrome_hash, firefox_hash,
            "Chrome and Firefox profiles must produce different JA3 hashes"
        );
    }

    // -----------------------------------------------------------------------
    // T-5: JA3 hash is valid 32-char lowercase hex
    // -----------------------------------------------------------------------

    #[test]
    fn ja3_hash_is_valid_hex() {
        for profile in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Default] {
            let hash = compute_ja3_hash(profile);
            assert_eq!(
                hash.len(),
                MD5_HEX_LENGTH,
                "JA3 hash for {profile} should be {MD5_HEX_LENGTH} chars"
            );
            assert!(
                hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "JA3 hash for {profile} should be lowercase hex: {hash}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // T-6: JA3 components expose correct IANA cipher suite values
    // -----------------------------------------------------------------------

    #[test]
    fn ja3_components_cipher_suites() {
        let components = ja3_components(TlsProfile::Chrome);
        assert_eq!(
            components.cipher_suites,
            vec![
                IANA_TLS13_AES_256_GCM_SHA384,
                IANA_TLS13_CHACHA20_POLY1305_SHA256,
                IANA_TLS13_AES_128_GCM_SHA256,
            ]
        );

        let components = ja3_components(TlsProfile::Firefox);
        assert_eq!(
            components.cipher_suites,
            vec![
                IANA_TLS13_AES_128_GCM_SHA256,
                IANA_TLS13_CHACHA20_POLY1305_SHA256,
                IANA_TLS13_AES_256_GCM_SHA384,
            ]
        );
    }

    // -----------------------------------------------------------------------
    // T-7: JA3 components expose correct IANA group values
    // -----------------------------------------------------------------------

    #[test]
    fn ja3_components_groups() {
        // All profiles use the same group ordering
        for profile in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Default] {
            let components = ja3_components(profile);
            assert_eq!(
                components.groups,
                vec![IANA_X25519, IANA_SECP256R1, IANA_SECP384R1],
                "All profiles should have groups: X25519, secp256r1, secp384r1"
            );
        }
    }

    // -----------------------------------------------------------------------
    // T-8: build_crypto_provider returns provider with correct suite count
    // -----------------------------------------------------------------------

    #[test]
    fn provider_suite_count() {
        for profile in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Default] {
            let provider = build_crypto_provider(profile);
            assert_eq!(
                provider.cipher_suites.len(),
                TLS13_CIPHER_SUITE_COUNT,
                "Profile {profile} should have {TLS13_CIPHER_SUITE_COUNT} cipher suites"
            );
        }
    }

    // -----------------------------------------------------------------------
    // T-9: build_mimicked_client_config produces working quinn config
    // -----------------------------------------------------------------------

    #[test]
    fn mimicked_client_config_builds() {
        for profile in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Default] {
            let result = build_mimicked_client_config(profile, true);
            assert!(result.is_ok(), "build_mimicked_client_config should succeed for {profile}");
        }
    }

    // -----------------------------------------------------------------------
    // T-10: QUIC connection with Chrome profile succeeds
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn quic_connection_chrome_profile() {
        quic_connection_with_profile(TlsProfile::Chrome).await;
    }

    // -----------------------------------------------------------------------
    // T-11: QUIC connection with Firefox profile succeeds
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn quic_connection_firefox_profile() {
        quic_connection_with_profile(TlsProfile::Firefox).await;
    }

    // -----------------------------------------------------------------------
    // T-12: MASQUE datagram exchange with mimicked config succeeds
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn masque_datagram_with_mimicked_config() {
        use crate::transport::masque::{MasqueClient, MasqueProxy};

        let (cert, key) = crate::transport::quic::generate_self_signed_cert(vec![TEST_SERVER_NAME.to_string()]).expect("cert generation");

        let server_config = build_mimicked_server_config(TlsProfile::Chrome, vec![cert], key).expect("server config");
        let server_endpoint = quinn::Endpoint::server(server_config, TEST_BIND_ADDR.parse().expect("valid addr")).expect("server bind");
        let server_addr = server_endpoint.local_addr().expect("local addr");

        let client_config = build_mimicked_client_config(TlsProfile::Chrome, true).expect("client config");
        let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("valid addr")).expect("client bind");
        client_endpoint.set_default_client_config(client_config);

        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("accept");
            let connection = incoming.await.expect("connection");
            let proxy = MasqueProxy::accept(connection).await.expect("proxy accept");

            let payload = proxy.recv_datagram().await.expect("recv datagram");
            proxy.send_datagram(&payload).expect("send echo");

            (server_endpoint, proxy)
        });

        let connection = client_endpoint
            .connect(server_addr, TEST_SERVER_NAME)
            .expect("connect")
            .await
            .expect("connection");

        let client = MasqueClient::connect(connection).await.expect("masque connect");
        client.send_datagram(TEST_MASQUE_PAYLOAD).expect("send datagram");

        let echoed = client.recv_datagram().await.expect("recv echo");
        assert_eq!(echoed, TEST_MASQUE_PAYLOAD);

        let (_endpoint, _proxy) = server_handle.await.expect("server task");
    }

    // -----------------------------------------------------------------------
    // T-13: TlsProfile Display/FromStr round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn profile_display_fromstr_round_trip() {
        for profile in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Default] {
            let name = profile.to_string();
            let parsed: TlsProfile = name.parse().expect("parse should succeed");
            assert_eq!(parsed, profile, "round-trip failed for {profile}");
        }
    }

    #[test]
    fn profile_fromstr_case_insensitive() {
        assert_eq!("Chrome".parse::<TlsProfile>().unwrap(), TlsProfile::Chrome);
        assert_eq!("FIREFOX".parse::<TlsProfile>().unwrap(), TlsProfile::Firefox);
        assert_eq!("Default".parse::<TlsProfile>().unwrap(), TlsProfile::Default);
    }

    #[test]
    fn profile_fromstr_unknown_rejected() {
        let result = "safari".parse::<TlsProfile>();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.unknown, "safari");
    }

    // -----------------------------------------------------------------------
    // T-14: Default profile JA3 differs from Chrome profile JA3
    // -----------------------------------------------------------------------

    #[test]
    fn default_ja3_differs_from_chrome() {
        let default_hash = compute_ja3_hash(TlsProfile::Default);
        let chrome_hash = compute_ja3_hash(TlsProfile::Chrome);
        assert_ne!(default_hash, chrome_hash, "Default and Chrome should produce different JA3 hashes");
    }

    // -----------------------------------------------------------------------
    // T-15: JA3 string format is correct
    // -----------------------------------------------------------------------

    #[test]
    fn ja3_string_format() {
        let components = ja3_components(TlsProfile::Chrome);
        let ja3_str = components.to_ja3_string();

        // Format: TLSVersion,CipherSuites,,EllipticCurves,ECPointFormats
        // Extensions field is empty
        let expected = format!(
            "{},{}-{}-{},,{}-{}-{},{}",
            JA3_TLS_VERSION,
            IANA_TLS13_AES_256_GCM_SHA384,
            IANA_TLS13_CHACHA20_POLY1305_SHA256,
            IANA_TLS13_AES_128_GCM_SHA256,
            IANA_X25519,
            IANA_SECP256R1,
            IANA_SECP384R1,
            JA3_EC_POINT_FORMAT_UNCOMPRESSED,
        );
        assert_eq!(ja3_str, expected);
    }

    // -----------------------------------------------------------------------
    // T-16: JA3 components TLS version is 771
    // -----------------------------------------------------------------------

    #[test]
    fn ja3_components_tls_version() {
        for profile in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Default] {
            let components = ja3_components(profile);
            assert_eq!(
                components.tls_version, JA3_TLS_VERSION,
                "TLS version should be {JA3_TLS_VERSION} for {profile}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    const TEST_SERVER_NAME: &str = "localhost";
    const TEST_BIND_ADDR: &str = "127.0.0.1:0";
    const TEST_MASQUE_PAYLOAD: &[u8] = b"mimicry-test-payload";

    /// Helper: test QUIC connection establishment with a given profile.
    async fn quic_connection_with_profile(profile: TlsProfile) {
        let (cert, key) = crate::transport::quic::generate_self_signed_cert(vec![TEST_SERVER_NAME.to_string()]).expect("cert generation");

        let server_config = build_mimicked_server_config(profile, vec![cert], key).expect("server config");
        let server_endpoint = quinn::Endpoint::server(server_config, TEST_BIND_ADDR.parse().expect("valid addr")).expect("server bind");
        let server_addr = server_endpoint.local_addr().expect("local addr");

        let client_config = build_mimicked_client_config(profile, true).expect("client config");
        let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("valid addr")).expect("client bind");
        client_endpoint.set_default_client_config(client_config);

        let server_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("accept");
            let connection = incoming.await.expect("connection");
            let (mut send, mut recv) = connection.accept_bi().await.expect("accept_bi");
            let data = recv.read_to_end(1024).await.expect("read");
            send.write_all(&data).await.expect("write");
            send.finish().expect("finish");
            (server_endpoint, connection)
        });

        let connection = client_endpoint
            .connect(server_addr, TEST_SERVER_NAME)
            .expect("connect")
            .await
            .expect("connection");

        let (mut send, mut recv) = connection.open_bi().await.expect("open_bi");
        send.write_all(TEST_MASQUE_PAYLOAD).await.expect("write");
        send.finish().expect("finish");

        let data = recv.read_to_end(1024).await.expect("read");
        assert_eq!(data, TEST_MASQUE_PAYLOAD);

        let (_endpoint, _conn) = server_handle.await.expect("server task");
    }
}
