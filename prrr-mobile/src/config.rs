// FRD: specs/frds/FRD-M002-uniffi-interface.md

use base64::Engine;

use crate::MobileError;

const IMPORT_URL_PREFIX: &str = "prrr://import?config=";

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
    const MIN_MTU: u16 = 1280;
    const MAX_MTU: u16 = 1500;

    if config.mtu < MIN_MTU || config.mtu > MAX_MTU {
        return Err(MobileError::InvalidConfig {
            reason: format!("mtu must be between {} and {}, got {}", MIN_MTU, MAX_MTU, config.mtu),
        });
    }

    Ok(())
}

/// Parse VPN configuration from QR code data
///
/// Decodes a `prrr://import?config=<base64>` URL and parses the TOML config.
#[uniffi::export]
pub fn parse_qr_config(qr_data: String) -> Result<VpnConfig, MobileError> {
    // Decode base64
    let encoded = qr_data.strip_prefix(IMPORT_URL_PREFIX).ok_or_else(|| MobileError::InvalidConfig {
        reason: "missing prrr://import?config= prefix".to_string(),
    })?;

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| MobileError::InvalidConfig {
            reason: format!("base64 decode failed: {e}"),
        })?;

    let toml_str = String::from_utf8(bytes).map_err(|e| MobileError::InvalidConfig {
        reason: format!("UTF-8 decode failed: {e}"),
    })?;

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

    Ok(VpnConfig {
        client_name,
        server_endpoint,
        server_public_key,
        server_pq_public_key,
        client_private_key,
        assigned_ip,
        dns_servers,
        mtu,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_qr_config_minimal() {
        // Test mutant: verify we actually decode base64
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
mtu = 1280
"#;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(config_toml);
        let qr_data = format!("{}{}", IMPORT_URL_PREFIX, encoded);

        let result = parse_qr_config(qr_data);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());

        let config = result.unwrap();
        assert_eq!(config.client_name, "test-client");
        assert_eq!(config.server_endpoint, "vpn.example.com:443");
        assert_eq!(config.assigned_ip, "10.66.66.2/32");
        assert_eq!(config.dns_servers, vec!["1.1.1.1"]);
        assert_eq!(config.mtu, 1280);
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
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(invalid_toml);
        let qr_data = format!("{}{}", IMPORT_URL_PREFIX, encoded);

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
mtu = 1280
"#;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(config_toml);
        let qr_data = format!("{}{}", IMPORT_URL_PREFIX, encoded);

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
mtu = 1280
"#;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(config_toml);
        let qr_data = format!("{}{}", IMPORT_URL_PREFIX, encoded);

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
            mtu: 1280,
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
            mtu: 1280,
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
            mtu: 1280,
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
            mtu: 1280,
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
            mtu: 1280,
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
            mtu: 1280,
        };

        let result = validate_config(config);
        assert!(result.is_ok());
    }
}
