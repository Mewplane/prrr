// FRD: specs/frds/FRD-M002-uniffi-interface.md

use base64::Engine;

use crate::MobileError;

/// Config URL prefix (deflate-compressed + base64url).
const IMPORT_URL_PREFIX: &str = "prrr://import?z=";

/// VPN configuration for mobile clients
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct VpnConfig {
    /// Client name
    pub client_name: String,
    /// Server endpoint (e.g. "vpn.example.com:443")
    pub server_endpoint: String,
    /// Server X25519 public key (32 bytes)
    pub server_public_key: Vec<u8>,
    /// Server ML-KEM-768 public key (1184 bytes)
    pub server_pq_public_key: Vec<u8>,
    /// Client X25519 private key (32 bytes)
    pub client_private_key: Vec<u8>,
    /// Assigned IP address (CIDR format, e.g. "10.66.66.2/32")
    pub assigned_ip: String,
    /// DNS servers
    pub dns_servers: Vec<String>,
    /// MTU
    pub mtu: u16,
    /// Preferred HARP transport binding: "h2", "stream", or "poll" (None = auto-select)
    pub preferred_binding: Option<String>,
    /// Transport protocol: "harp" or "masque" (None = masque)
    pub transport_protocol: Option<String>,
    /// Strict full-tunnel: when `Some(true)`, capture the local LAN too (disable
    /// the default RFC1918 local-LAN auto-exclusion). `None`/`Some(false)` keep
    /// LAN auto-exclusion on so a sibling on the same LAN stays reachable.
    pub full_tunnel: Option<bool>,
}

/// Validate VPN configuration
///
/// Checks that all required fields are present and valid.
#[uniffi::export]
pub fn validate_config(config: VpnConfig) -> Result<(), MobileError> {
    // Validate endpoint is non-empty
    if config.server_endpoint.is_empty() {
        return Err(MobileError::InvalidConfig {
            reason: "server_endpoint is empty".to_string(),
        });
    }

    // Validate key lengths (32 bytes for X25519, 1184 bytes for ML-KEM-768)
    const X25519_KEY_LEN: usize = 32;
    const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;

    if config.server_public_key.len() != X25519_KEY_LEN {
        return Err(MobileError::InvalidConfig {
            reason: format!(
                "server_public_key must be {} bytes, got {}",
                X25519_KEY_LEN,
                config.server_public_key.len()
            ),
        });
    }

    if config.server_pq_public_key.len() != MLKEM768_PUBLIC_KEY_LEN {
        return Err(MobileError::InvalidConfig {
            reason: format!(
                "server_pq_public_key must be {} bytes, got {}",
                MLKEM768_PUBLIC_KEY_LEN,
                config.server_pq_public_key.len()
            ),
        });
    }

    if config.client_private_key.len() != X25519_KEY_LEN {
        return Err(MobileError::InvalidConfig {
            reason: format!(
                "client_private_key must be {} bytes, got {}",
                X25519_KEY_LEN,
                config.client_private_key.len()
            ),
        });
    }

    // Validate assigned_ip is valid CIDR format (basic check)
    if !config.assigned_ip.contains('/') {
        return Err(MobileError::InvalidConfig {
            reason: "assigned_ip must be in CIDR format (e.g. 10.66.66.2/32)".to_string(),
        });
    }

    // Validate DNS servers is non-empty
    if config.dns_servers.is_empty() {
        return Err(MobileError::InvalidConfig {
            reason: "dns_servers must not be empty".to_string(),
        });
    }

    // Validate MTU is in valid range
    const MIN_MTU: u16 = 576;
    const MAX_MTU: u16 = 1500;

    if config.mtu < MIN_MTU || config.mtu > MAX_MTU {
        return Err(MobileError::InvalidConfig {
            reason: format!("mtu must be between {MIN_MTU} and {MAX_MTU}, got {}", config.mtu),
        });
    }

    Ok(())
}

/// Parse VPN configuration from QR code data
///
/// Decodes a `prrr://import?z=<base64>` URL (deflate-compressed TOML) and
/// parses the config.
#[uniffi::export]
pub fn parse_qr_config(qr_data: String) -> Result<VpnConfig, MobileError> {
    let encoded = qr_data.strip_prefix(IMPORT_URL_PREFIX).ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing prrr://import?z= prefix".to_string(),
    })?;

    let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| MobileError::InvalidConfig {
            reason: format!("base64 decode failed: {e}"),
        })?;

    use std::io::Read;

    use flate2::read::DeflateDecoder;
    let mut decoder = DeflateDecoder::new(&compressed[..]);
    let toml_str = {
        let mut s = String::new();
        decoder.read_to_string(&mut s).map_err(|e| MobileError::InvalidConfig {
            reason: format!("deflate decompress failed: {e}"),
        })?;
        s
    };

    // Parse TOML
    let config: TomlConfig = toml::from_str(&toml_str).map_err(|e| MobileError::InvalidConfig {
        reason: format!("TOML parse failed: {e}"),
    })?;

    // Convert to VpnConfig
    convert_toml_to_vpn_config(config)
}

/// Internal TOML structure matching prrr client config format
#[derive(Debug, serde::Deserialize)]
struct TomlConfig {
    client: Option<TomlClient>,
    server: Option<TomlServer>,
    interface: Option<TomlInterface>,
    routing: Option<TomlRouting>,
}

#[derive(Debug, serde::Deserialize)]
struct TomlRouting {
    full_tunnel: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
struct TomlClient {
    name: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct TomlServer {
    endpoint: Option<String>,
    public_key: Option<String>,
    pq_public_key: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct TomlInterface {
    private_key: Option<String>,
    address: Option<String>,
    dns: Option<Vec<String>>,
    mtu: Option<u16>,
    preferred_binding: Option<String>,
    transport_protocol: Option<String>,
}

fn convert_toml_to_vpn_config(config: TomlConfig) -> Result<VpnConfig, MobileError> {
    let client_name = config.client.and_then(|c| c.name).ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing [client].name".to_string(),
    })?;

    let server = config.server.ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing [server] section".to_string(),
    })?;

    let server_endpoint = server.endpoint.ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing [server].endpoint".to_string(),
    })?;

    let server_public_key_b64 = server.public_key.ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing [server].public_key".to_string(),
    })?;

    let server_pq_public_key_b64 = server.pq_public_key.ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing [server].pq_public_key".to_string(),
    })?;

    let interface = config.interface.ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing [interface] section".to_string(),
    })?;

    let client_private_key_b64 = interface.private_key.ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing [interface].private_key".to_string(),
    })?;

    let assigned_ip = interface.address.ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing [interface].address".to_string(),
    })?;

    let dns_servers = interface.dns.ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing [interface].dns".to_string(),
    })?;

    let mtu = interface.mtu.ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing [interface].mtu".to_string(),
    })?;

    // Decode base64 keys
    let server_public_key = base64::engine::general_purpose::STANDARD
        .decode(&server_public_key_b64)
        .map_err(|e| MobileError::InvalidConfig {
            reason: format!("invalid server public_key base64: {e}"),
        })?;

    let server_pq_public_key = base64::engine::general_purpose::STANDARD
        .decode(&server_pq_public_key_b64)
        .map_err(|e| MobileError::InvalidConfig {
            reason: format!("invalid server pq_public_key base64: {e}"),
        })?;

    let client_private_key = base64::engine::general_purpose::STANDARD
        .decode(&client_private_key_b64)
        .map_err(|e| MobileError::InvalidConfig {
            reason: format!("invalid interface private_key base64: {e}"),
        })?;

    let preferred_binding = interface.preferred_binding;
    let transport_protocol = interface.transport_protocol;
    let full_tunnel = config.routing.and_then(|r| r.full_tunnel);

    Ok(VpnConfig {
        client_name,
        server_endpoint,
        server_public_key,
        server_pq_public_key,
        client_private_key,
        assigned_ip,
        dns_servers,
        mtu,
        preferred_binding,
        transport_protocol,
        full_tunnel,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deflate-compress and base64url-encode, returning a `prrr://import?z=...` URL.
    fn compress_to_qr_url(toml: &str) -> String {
        use std::io::Write;

        use flate2::{write::DeflateEncoder, Compression};

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(toml.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
        format!("{IMPORT_URL_PREFIX}{encoded}")
    }

    #[test]
    fn test_parse_valid_qr_config_minimal() {
        // Test mutant: verify we actually decode deflate + base64
        let config_toml = r#"
[client]
name = "test-client"

[server]
endpoint = "vpn.example.com:443"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
pq_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[interface]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
address = "10.66.66.2/32"
dns = ["1.1.1.1"]
mtu = 1100
"#;
        let qr_data = compress_to_qr_url(config_toml);

        let result = parse_qr_config(qr_data);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());

        let config = result.unwrap();
        assert_eq!(config.client_name, "test-client");
        assert_eq!(config.server_endpoint, "vpn.example.com:443");
        assert_eq!(config.assigned_ip, "10.66.66.2/32");
        assert_eq!(config.dns_servers, vec!["1.1.1.1"]);
        assert_eq!(config.mtu, 1100);
        // FRD-001: full_tunnel absent → None (LAN auto-exclusion on by default).
        assert_eq!(config.full_tunnel, None);
    }

    // FRD-001: [routing].full_tunnel = true is parsed from the QR config.
    #[test]
    fn test_parse_qr_config_full_tunnel_true() {
        let config_toml = format!(
            r#"[client]
name = "strict-client"

[server]
endpoint = "vpn.example.com:443"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
pq_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[interface]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
address = "10.66.66.2/32"
dns = ["1.1.1.1"]
mtu = 1100

[routing]
full_tunnel = true
"#
        );
        let qr_data = compress_to_qr_url(&config_toml);
        let config = parse_qr_config(qr_data).expect("parse full_tunnel config");
        assert_eq!(config.full_tunnel, Some(true));
    }

    #[test]
    fn test_parse_invalid_prefix() {
        // Test mutant: verify prefix validation
        let result = parse_qr_config("https://example.com".to_string());
        assert!(matches!(result, Err(MobileError::InvalidConfig { .. })));
        if let Err(MobileError::InvalidConfig { reason }) = result {
            assert!(reason.contains("prefix"));
        }
    }

    #[test]
    fn test_parse_invalid_base64() {
        // Test mutant: verify base64 validation
        let qr_data = format!("{}!!!invalid!!!", IMPORT_URL_PREFIX);
        let result = parse_qr_config(qr_data);
        assert!(matches!(result, Err(MobileError::InvalidConfig { .. })));
        if let Err(MobileError::InvalidConfig { reason }) = result {
            assert!(reason.contains("base64"));
        }
    }

    #[test]
    fn test_parse_invalid_toml() {
        // Test mutant: verify TOML validation
        let invalid_toml = "not valid toml {{{";
        let qr_data = compress_to_qr_url(invalid_toml);

        let result = parse_qr_config(qr_data);
        assert!(matches!(result, Err(MobileError::InvalidConfig { .. })));
        if let Err(MobileError::InvalidConfig { reason }) = result {
            assert!(reason.contains("TOML"));
        }
    }

    #[test]
    fn test_parse_missing_client_name() {
        // Test mutant: verify required field validation
        let config_toml = r#"
[server]
endpoint = "vpn.example.com:443"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
pq_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[interface]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
address = "10.66.66.2/32"
dns = ["1.1.1.1"]
mtu = 1100
"#;
        let qr_data = compress_to_qr_url(config_toml);

        let result = parse_qr_config(qr_data);
        assert!(matches!(result, Err(MobileError::InvalidConfig { .. })));
        if let Err(MobileError::InvalidConfig { reason }) = result {
            assert!(reason.contains("client"));
        }
    }

    #[test]
    fn test_parse_missing_server_section() {
        // Test mutant: verify server section validation
        let config_toml = r#"
[client]
name = "test"

[interface]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
address = "10.66.66.2/32"
dns = ["1.1.1.1"]
mtu = 1100
"#;
        let qr_data = compress_to_qr_url(config_toml);

        let result = parse_qr_config(qr_data);
        assert!(matches!(result, Err(MobileError::InvalidConfig { .. })));
        if let Err(MobileError::InvalidConfig { reason }) = result {
            assert!(reason.contains("server"));
        }
    }

    #[test]
    fn test_validate_empty_endpoint() {
        // Test mutant: verify endpoint validation
        let config = VpnConfig {
            client_name: "test".to_string(),
            server_endpoint: String::new(),
            server_public_key: vec![0u8; 32],
            server_pq_public_key: vec![0u8; 1184],
            client_private_key: vec![0u8; 32],
            assigned_ip: "10.66.66.2/32".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            mtu: 1100,
            preferred_binding: None,
            transport_protocol: None,
            full_tunnel: None,
        };

        let result = validate_config(config);
        assert!(matches!(result, Err(MobileError::InvalidConfig { .. })));
        if let Err(MobileError::InvalidConfig { reason }) = result {
            assert!(reason.contains("endpoint"));
        }
    }

    #[test]
    fn test_validate_invalid_key_length() {
        // Test mutant: verify key length validation
        let config = VpnConfig {
            client_name: "test".to_string(),
            server_endpoint: "vpn.example.com:443".to_string(),
            server_public_key: vec![0u8; 16], // Wrong length, should be 32
            server_pq_public_key: vec![0u8; 1184],
            client_private_key: vec![0u8; 32],
            assigned_ip: "10.66.66.2/32".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            mtu: 1100,
            preferred_binding: None,
            transport_protocol: None,
            full_tunnel: None,
        };

        let result = validate_config(config);
        assert!(matches!(result, Err(MobileError::InvalidConfig { .. })));
        if let Err(MobileError::InvalidConfig { reason }) = result {
            assert!(reason.contains("32 bytes"));
        }
    }

    #[test]
    fn test_validate_invalid_pq_key_length() {
        // Test mutant: verify PQ key length validation
        let config = VpnConfig {
            client_name: "test".to_string(),
            server_endpoint: "vpn.example.com:443".to_string(),
            server_public_key: vec![0u8; 32],
            server_pq_public_key: vec![0u8; 100], // Wrong length, should be 1184
            client_private_key: vec![0u8; 32],
            assigned_ip: "10.66.66.2/32".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            mtu: 1100,
            preferred_binding: None,
            transport_protocol: None,
            full_tunnel: None,
        };

        let result = validate_config(config);
        assert!(matches!(result, Err(MobileError::InvalidConfig { .. })));
        if let Err(MobileError::InvalidConfig { reason }) = result {
            assert!(reason.contains("1184 bytes"));
        }
    }

    #[test]
    fn test_validate_missing_cidr() {
        // Test mutant: verify CIDR format validation
        let config = VpnConfig {
            client_name: "test".to_string(),
            server_endpoint: "vpn.example.com:443".to_string(),
            server_public_key: vec![0u8; 32],
            server_pq_public_key: vec![0u8; 1184],
            client_private_key: vec![0u8; 32],
            assigned_ip: "10.66.66.2".to_string(), // Missing /32
            dns_servers: vec!["1.1.1.1".to_string()],
            mtu: 1100,
            preferred_binding: None,
            transport_protocol: None,
            full_tunnel: None,
        };

        let result = validate_config(config);
        assert!(matches!(result, Err(MobileError::InvalidConfig { .. })));
        if let Err(MobileError::InvalidConfig { reason }) = result {
            assert!(reason.contains("CIDR"));
        }
    }

    #[test]
    fn test_validate_empty_dns() {
        // Test mutant: verify DNS servers validation
        let config = VpnConfig {
            client_name: "test".to_string(),
            server_endpoint: "vpn.example.com:443".to_string(),
            server_public_key: vec![0u8; 32],
            server_pq_public_key: vec![0u8; 1184],
            client_private_key: vec![0u8; 32],
            assigned_ip: "10.66.66.2/32".to_string(),
            dns_servers: vec![],
            mtu: 1100,
            preferred_binding: None,
            transport_protocol: None,
            full_tunnel: None,
        };

        let result = validate_config(config);
        assert!(matches!(result, Err(MobileError::InvalidConfig { .. })));
        if let Err(MobileError::InvalidConfig { reason }) = result {
            assert!(reason.contains("dns"));
        }
    }

    #[test]
    fn test_validate_invalid_mtu() {
        // Test mutant: verify MTU range validation
        let config = VpnConfig {
            client_name: "test".to_string(),
            server_endpoint: "vpn.example.com:443".to_string(),
            server_public_key: vec![0u8; 32],
            server_pq_public_key: vec![0u8; 1184],
            client_private_key: vec![0u8; 32],
            assigned_ip: "10.66.66.2/32".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            mtu: 9000, // Too large
            preferred_binding: None,
            transport_protocol: None,
            full_tunnel: None,
        };

        let result = validate_config(config);
        assert!(matches!(result, Err(MobileError::InvalidConfig { .. })));
        if let Err(MobileError::InvalidConfig { reason }) = result {
            assert!(reason.contains("mtu"));
        }
    }

    #[test]
    fn test_validate_valid_config() {
        // Test mutant: verify valid config passes
        let config = VpnConfig {
            client_name: "test".to_string(),
            server_endpoint: "vpn.example.com:443".to_string(),
            server_public_key: vec![0u8; 32],
            server_pq_public_key: vec![0u8; 1184],
            client_private_key: vec![0u8; 32],
            assigned_ip: "10.66.66.2/32".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            mtu: 1100,
            preferred_binding: None,
            transport_protocol: None,
            full_tunnel: None,
        };

        let result = validate_config(config);
        assert!(result.is_ok());
    }

    /// Helper: build a valid VpnConfig with a custom MTU.
    fn config_with_mtu(mtu: u16) -> VpnConfig {
        VpnConfig {
            client_name: "test".to_string(),
            server_endpoint: "vpn.example.com:443".to_string(),
            server_public_key: vec![0u8; 32],
            server_pq_public_key: vec![0u8; 1184],
            client_private_key: vec![0u8; 32],
            assigned_ip: "10.66.66.2/32".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            mtu,
            preferred_binding: None,
            transport_protocol: None,
            full_tunnel: None,
        }
    }

    /// The default MTU (1100) must be accepted by mobile validation.
    #[test]
    fn validate_accepts_default_mtu() {
        assert!(validate_config(config_with_mtu(1100)).is_ok());
    }

    /// MTU boundary values: MIN_MTU (576), MAX_MTU (1500), and just outside.
    #[test]
    fn validate_mtu_boundaries() {
        assert!(validate_config(config_with_mtu(576)).is_ok(), "MIN_MTU should pass");
        assert!(validate_config(config_with_mtu(1100)).is_ok(), "default should pass");
        assert!(validate_config(config_with_mtu(1500)).is_ok(), "MAX_MTU should pass");
        assert!(validate_config(config_with_mtu(575)).is_err(), "below MIN should fail");
        assert!(validate_config(config_with_mtu(1501)).is_err(), "above MAX should fail");
    }

    // --- Multi-frame QR protocol tests ---

    const MULTI_FRAME_PREFIX: &str = "prrr://import?f=";
    const MULTI_FRAME_MAX_CHUNK: usize = 300;

    /// Split compressed payload into multi-frame URLs (mirrors JS buildMultiFrameUrls).
    fn build_multiframe_urls(payload: &str) -> Vec<String> {
        let chunks: Vec<&str> = payload
            .as_bytes()
            .chunks(MULTI_FRAME_MAX_CHUNK)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let total = chunks.len();
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| format!("{MULTI_FRAME_PREFIX}{}.{total}&z={chunk}", i + 1))
            .collect()
    }

    /// Reassemble multi-frame URLs back into a single-frame URL (mirrors Kotlin logic).
    fn reassemble_multiframe(frame_urls: &[String]) -> String {
        let mut chunks: std::collections::BTreeMap<usize, String> = std::collections::BTreeMap::new();
        let mut total = 0;
        for url in frame_urls {
            let params = url.strip_prefix("prrr://import?").unwrap();
            let f_param = params.split("&z=").next().unwrap().strip_prefix("f=").unwrap();
            let chunk_data = params.split("&z=").nth(1).unwrap_or("");
            let parts: Vec<&str> = f_param.split('.').collect();
            let index: usize = parts[0].parse().unwrap();
            total = parts[1].parse().unwrap();
            chunks.insert(index, chunk_data.to_string());
        }
        let payload: String = (1..=total).map(|i| chunks[&i].as_str()).collect();
        format!("{IMPORT_URL_PREFIX}{payload}")
    }

    #[test]
    fn test_multiframe_split_and_reassemble() {
        // Build a realistic config TOML with ML-KEM-768 key.
        // Use varied byte pattern (not uniform) so deflate can't compress it
        // down below the multi-frame threshold.
        let pq_key: Vec<u8> = (0..1184).map(|i| (i % 251) as u8).collect();
        let config_toml = format!(
            r#"[client]
name = "test-phone"

[server]
endpoint = "vpn.example.com:443"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
pq_public_key = "{}"

[interface]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
address = "10.66.66.2/32"
dns = ["1.1.1.1", "8.8.8.8"]
mtu = 1100
"#,
            base64::engine::general_purpose::STANDARD.encode(&pq_key)
        );

        // Compress to get the payload
        let qr_url = compress_to_qr_url(&config_toml);
        let payload = qr_url.strip_prefix(IMPORT_URL_PREFIX).unwrap();

        // Verify payload is large enough to require multiple frames
        assert!(
            payload.len() > MULTI_FRAME_MAX_CHUNK,
            "payload should exceed single chunk: {} chars",
            payload.len()
        );

        // Split into frames
        let frames = build_multiframe_urls(payload);
        assert!(frames.len() > 1, "should produce multiple frames: {}", frames.len());

        // Each frame should be small enough for easy QR scanning
        for frame in &frames {
            assert!(frame.len() < 400, "frame too large for easy scanning: {} chars", frame.len());
        }

        // Reassemble (simulating Kotlin collector)
        let reassembled = reassemble_multiframe(&frames);

        // The reassembled URL should parse successfully
        let result = parse_qr_config(reassembled);
        assert!(result.is_ok(), "reassembled config should parse: {:?}", result.err());

        let config = result.unwrap();
        assert_eq!(config.client_name, "test-phone");
        assert_eq!(config.server_endpoint, "vpn.example.com:443");
        assert_eq!(config.assigned_ip, "10.66.66.2/32");
    }

    #[test]
    fn test_multiframe_shuffled_order() {
        // Frames can arrive in any order — reassembly should still work
        let pq_key: Vec<u8> = (0..1184).map(|i| ((i * 7 + 3) % 251) as u8).collect();
        let config_toml = format!(
            r#"[client]
name = "shuffle-test"

[server]
endpoint = "vpn.example.com:443"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
pq_public_key = "{}"

[interface]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
address = "10.66.66.5/32"
dns = ["1.1.1.1"]
mtu = 1100
"#,
            base64::engine::general_purpose::STANDARD.encode(&pq_key)
        );

        let qr_url = compress_to_qr_url(&config_toml);
        let payload = qr_url.strip_prefix(IMPORT_URL_PREFIX).unwrap();
        let mut frames = build_multiframe_urls(payload);

        // Reverse to simulate out-of-order scanning
        frames.reverse();

        let reassembled = reassemble_multiframe(&frames);
        let result = parse_qr_config(reassembled);
        assert!(result.is_ok(), "shuffled frames should reassemble: {:?}", result.err());
        assert_eq!(result.unwrap().client_name, "shuffle-test");
    }

    #[test]
    fn test_multiframe_frame_format() {
        let payload = "ABCDEFGHIJ";
        // Use tiny chunk size for testing
        let chunks: Vec<&str> = payload.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect();
        let total = chunks.len();
        let frames: Vec<String> = chunks
            .iter()
            .enumerate()
            .map(|(i, chunk)| format!("{MULTI_FRAME_PREFIX}{}.{total}&z={chunk}", i + 1))
            .collect();

        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], "prrr://import?f=1.3&z=ABCD");
        assert_eq!(frames[1], "prrr://import?f=2.3&z=EFGH");
        assert_eq!(frames[2], "prrr://import?f=3.3&z=IJ");
    }
}
