// FRD: specs/frds/FRD-P009B.md

//! CLI command handlers for `prrr server client` and `prrr client import`.
//!
//! Each handler takes the minimum required state (registry, server context)
//! and performs the requested operation, printing results to stdout.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::config::{DEFAULT_IDENTITY_KEY_PATH, DEFAULT_PQ_KEY_PATH, ServerArgs, ServerClientAction, ServerConfig};
use crate::distribution::{ServerContext, decode_import_url, generate_client_config, generate_qr_svg};
use crate::handshake::noise_ik::KeyPair;
use crate::registry::ClientRegistry;

/// Default client configuration directory.
const DEFAULT_CLIENT_CONFIG_DIR: &str = ".config/prrr";

/// Default client configuration filename.
const DEFAULT_CLIENT_CONFIG_FILENAME: &str = "client.toml";

/// URL scheme prefix for prrr import URLs.
const IMPORT_URL_PREFIX: &str = "prrr://";

/// Handle a `prrr server client <action>` subcommand.
///
/// Dispatches to the appropriate handler based on the action variant.
/// For `Export`, loads server keys to build `ServerContext`.
pub fn handle_server_client_action(
    registry: &mut ClientRegistry,
    action: &ServerClientAction,
    config: &ServerConfig,
    server_args: &ServerArgs,
) -> anyhow::Result<()> {
    match action {
        ServerClientAction::Add { name, qr } => {
            let ctx = build_server_context(config, server_args)?;
            handle_client_add(registry, &ctx, name, *qr)
        }
        ServerClientAction::List => handle_client_list(registry),
        ServerClientAction::Remove { name } => handle_client_remove(registry, name),
        ServerClientAction::Export { name, qr, output } => {
            let ctx = build_server_context(config, server_args)?;
            handle_client_export(registry, &ctx, name, *qr, output.as_deref())
        }
    }
}

/// Build a [`ServerContext`] from config and CLI args for config generation.
fn build_server_context(config: &ServerConfig, server_args: &ServerArgs) -> anyhow::Result<ServerContext> {
    let identity_key_path = config
        .crypto
        .as_ref()
        .and_then(|c| c.identity_key_path.as_deref())
        .unwrap_or(DEFAULT_IDENTITY_KEY_PATH);
    let pq_key_path = config
        .crypto
        .as_ref()
        .and_then(|c| c.pq_key_path.as_deref())
        .unwrap_or(DEFAULT_PQ_KEY_PATH);

    let key_store = crate::keys::KeyStore::load_or_generate(Path::new(identity_key_path), Path::new(pq_key_path))?;

    let noise_public_key = *key_store.noise_keypair().public_key();
    let kem_public_key = key_store.kem_keypair().encapsulation_key_bytes();
    let server_name = config
        .server
        .as_ref()
        .and_then(|s| s.server_name.as_deref())
        .unwrap_or(&server_args.server_name);
    let port = server_args.listen.port();
    let endpoint = format!("{server_name}:{port}");

    let dns_servers = config
        .network
        .as_ref()
        .and_then(|n| n.dns_servers.as_ref())
        .cloned()
        .unwrap_or_else(|| crate::config::DEFAULT_DNS_SERVERS.iter().map(|s| (*s).to_string()).collect());
    let mtu = config.network.as_ref().and_then(|n| n.mtu).unwrap_or(crate::config::DEFAULT_MTU);
    let transport_protocol = config
        .transports
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find_map(|e| match e {
            crate::config::TransportEntry::Harp(h) if h.enabled != Some(false) => Some("harp"),
            crate::config::TransportEntry::Masque(m) if m.enabled != Some(false) => Some("masque"),
            _ => None,
        })
        .unwrap_or(crate::config::DEFAULT_TRANSPORT_PROTOCOL)
        .to_string();

    Ok(ServerContext {
        endpoint,
        server_name: server_name.to_string(),
        noise_public_key,
        kem_public_key,
        dns_servers,
        mtu,
        transport_protocol,
    })
}

/// Register a new VPN client and output a complete ready-to-use config.
///
/// The config includes the inline `private_key` and works for both Linux CLI
/// (`prrr client --config <file>`) and mobile import (QR scan). The private
/// key is generated here and never stored on the server — this is the only
/// time it is available.
///
/// With `--qr`, also writes a QR code SVG to `<name>.svg` for mobile scanning.
fn handle_client_add(registry: &mut ClientRegistry, ctx: &ServerContext, name: &str, qr: bool) -> anyhow::Result<()> {
    let keypair = KeyPair::generate()?;
    let public_key = *keypair.public_key();

    let record = registry.add(name, public_key, None)?;

    let config_toml = generate_client_config(ctx, &record, Some(keypair.private_key_bytes()))
        .map_err(|e| anyhow::anyhow!("config generation failed: {e}"))?;

    eprintln!("Client registered:");
    eprintln!("  Name:       {}", record.name);
    eprintln!("  ID:         {}", record.id);
    eprintln!("  IP Address: {}", record.ip_address);

    if qr {
        let svg = generate_qr_svg(&config_toml)
            .map_err(|e| anyhow::anyhow!("QR generation failed: {e}"))?;
        let qr_path = format!("{name}.svg");
        std::fs::write(&qr_path, &svg)?;
        eprintln!("  QR code:    {qr_path}");
    }

    eprintln!();
    eprintln!("Config written to stdout. Save it now — the private key will not be shown again.");
    eprintln!("Usage: prrr server client add {name} > {name}.toml");
    eprintln!();

    // Config to stdout (pipe-friendly)
    print!("{config_toml}");

    Ok(())
}

/// List all registered (non-revoked) clients.
fn handle_client_list(registry: &ClientRegistry) -> anyhow::Result<()> {
    let clients = registry.list();

    if clients.is_empty() {
        println!("No clients registered.");
        return Ok(());
    }

    println!("{:<36}  {:<20}  {:<15}  {:<10}", "ID", "NAME", "IP ADDRESS", "STATUS");
    println!("{}", "-".repeat(85));

    for client in &clients {
        println!(
            "{:<36}  {:<20}  {:<15}  {:<10}",
            client.id,
            client.name,
            client.ip_address,
            client.status.as_str(),
        );
    }

    println!();
    println!("Total: {} client(s)", clients.len());

    Ok(())
}

/// Revoke a client by name.
fn handle_client_remove(registry: &mut ClientRegistry, name: &str) -> anyhow::Result<()> {
    let record = registry
        .get_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("client not found: {name}"))?;

    registry.remove(record.id)?;
    println!("Client \"{}\" (ID: {}) revoked.", record.name, record.id);

    Ok(())
}

/// Export client configuration as TOML or QR code SVG.
fn handle_client_export(registry: &ClientRegistry, ctx: &ServerContext, name: &str, qr: bool, output: Option<&Path>) -> anyhow::Result<()> {
    let record = registry
        .get_by_name(name)
        .ok_or_else(|| anyhow::anyhow!("client not found: {name}"))?;

    let config_toml = generate_client_config(ctx, &record, None).map_err(|e| anyhow::anyhow!("config generation failed: {e}"))?;

    let content = if qr {
        generate_qr_svg(&config_toml).map_err(|e| anyhow::anyhow!("QR generation failed: {e}"))?
    } else {
        config_toml
    };

    match output {
        Some(path) => {
            std::fs::write(path, &content)?;
            let kind = if qr { "QR code SVG" } else { "TOML config" };
            println!("{kind} written to {}", path.display());
        }
        None => {
            print!("{content}");
        }
    }

    Ok(())
}

/// Import client configuration from a file path or `prrr://import` URL.
///
/// Saves to `$HOME/.config/prrr/client.toml` by default.
pub fn handle_client_import(source: &str) -> anyhow::Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let config_dir = Path::new(&home).join(DEFAULT_CLIENT_CONFIG_DIR);
    import_config_to(source, &config_dir)
}

/// Import client configuration to a specific directory.
///
/// Reads from file path or `prrr://import` URL, validates as client TOML,
/// and writes to `<config_dir>/client.toml`.
pub fn import_config_to(source: &str, config_dir: &Path) -> anyhow::Result<()> {
    let config_toml = if source.starts_with(IMPORT_URL_PREFIX) {
        decode_import_url(source).map_err(|e| anyhow::anyhow!("URL decode failed: {e}"))?
    } else {
        std::fs::read_to_string(source).map_err(|e| anyhow::anyhow!("failed to read {source}: {e}"))?
    };

    // Validate TOML parses as client config
    let _: crate::config::ClientConfigFile = toml::from_str(&config_toml).map_err(|e| anyhow::anyhow!("invalid client config: {e}"))?;

    std::fs::create_dir_all(config_dir)?;
    let config_path = config_dir.join(DEFAULT_CLIENT_CONFIG_FILENAME);
    std::fs::write(&config_path, &config_toml)?;

    println!("Client configuration imported to {}", config_path.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P009B.md
    use super::*;
    use crate::registry::ClientRegistry;

    const TEST_SUBNET: &str = "10.66.66.0/24";
    const TEST_CLIENT_NAME: &str = "test-alice";

    fn test_registry() -> ClientRegistry {
        ClientRegistry::new(TEST_SUBNET).expect("valid subnet")
    }

    fn test_server_context() -> ServerContext {
        ServerContext {
            endpoint: "127.0.0.1:443".to_string(),
            server_name: "localhost".to_string(),
            noise_public_key: [0xAA; 32],
            kem_public_key: vec![0xBB; 64],
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            mtu: 1280,
            transport_protocol: "masque".to_string(),
        }
    }

    // AC-B11: handle_client_add creates client and returns record
    #[test]
    fn cli_add_creates_client() {
        let mut registry = test_registry();
        handle_client_add(&mut registry, &test_server_context(), TEST_CLIENT_NAME, false).expect("add should succeed");

        let record = registry.get_by_name(TEST_CLIENT_NAME).expect("client should exist");
        assert_eq!(record.name, TEST_CLIENT_NAME);
    }

    // AC-B11b: handle_client_add rejects duplicate name
    #[test]
    fn cli_add_duplicate_name_fails() {
        let mut registry = test_registry();
        handle_client_add(&mut registry, &test_server_context(), TEST_CLIENT_NAME, false).expect("first add");
        let err = handle_client_add(&mut registry, &test_server_context(), TEST_CLIENT_NAME, false);
        assert!(err.is_err(), "duplicate name should fail");
    }

    // AC-B12: handle_client_list returns formatted output
    #[test]
    fn cli_list_returns_clients() {
        let mut registry = test_registry();
        handle_client_add(&mut registry, &test_server_context(), "alice", false).expect("add alice");
        handle_client_add(&mut registry, &test_server_context(), "bob", false).expect("add bob");

        // list should succeed (output goes to stdout)
        handle_client_list(&registry).expect("list should succeed");
        assert_eq!(registry.list().len(), 2);
    }

    // AC-B12b: handle_client_list with empty registry
    #[test]
    fn cli_list_empty_registry() {
        let registry = test_registry();
        handle_client_list(&registry).expect("list empty should succeed");
    }

    // AC-B13: handle_client_remove revokes client by name
    #[test]
    fn cli_remove_revokes_client() {
        let mut registry = test_registry();
        handle_client_add(&mut registry, &test_server_context(), TEST_CLIENT_NAME, false).expect("add");
        assert_eq!(registry.count(), 1);

        handle_client_remove(&mut registry, TEST_CLIENT_NAME).expect("remove should succeed");
        assert_eq!(registry.count(), 0);
        assert!(registry.get_by_name(TEST_CLIENT_NAME).is_none());
    }

    // AC-B13b: handle_client_remove fails for unknown client
    #[test]
    fn cli_remove_unknown_fails() {
        let mut registry = test_registry();
        let err = handle_client_remove(&mut registry, "nonexistent");
        assert!(err.is_err());
    }

    // AC-B14: handle_client_export produces valid TOML
    #[test]
    fn cli_export_produces_toml() {
        let mut registry = test_registry();
        handle_client_add(&mut registry, &test_server_context(), TEST_CLIENT_NAME, false).expect("add");
        let ctx = test_server_context();

        // Export to file
        let dir = tempfile::tempdir().expect("tempdir");
        let output_path = dir.path().join("client.toml");

        handle_client_export(&registry, &ctx, TEST_CLIENT_NAME, false, Some(&output_path)).expect("export should succeed");

        let content = std::fs::read_to_string(&output_path).expect("read output");
        assert!(content.contains("[client]"), "should contain [client] section");
        assert!(content.contains("[server]"), "should contain [server] section");
        assert!(content.contains(TEST_CLIENT_NAME), "should contain client name");
    }

    // AC-B15: handle_client_export --qr produces SVG QR code
    #[test]
    fn cli_export_qr_produces_svg() {
        let mut registry = test_registry();
        handle_client_add(&mut registry, &test_server_context(), TEST_CLIENT_NAME, false).expect("add");
        let ctx = test_server_context();

        let dir = tempfile::tempdir().expect("tempdir");
        let output_path = dir.path().join("client.svg");

        handle_client_export(&registry, &ctx, TEST_CLIENT_NAME, true, Some(&output_path)).expect("export QR should succeed");

        let content = std::fs::read_to_string(&output_path).expect("read output");
        assert!(content.contains("<svg"), "should contain SVG tag");
    }

    // AC-B16: handle_client_export --output writes to file
    #[test]
    fn cli_export_writes_to_file() {
        let mut registry = test_registry();
        handle_client_add(&mut registry, &test_server_context(), TEST_CLIENT_NAME, false).expect("add");
        let ctx = test_server_context();

        let dir = tempfile::tempdir().expect("tempdir");
        let output_path = dir.path().join("exported.toml");

        handle_client_export(&registry, &ctx, TEST_CLIENT_NAME, false, Some(&output_path)).expect("export should succeed");

        assert!(output_path.exists(), "output file should be created");
        let content = std::fs::read_to_string(&output_path).expect("read");
        assert!(!content.is_empty(), "output should not be empty");
    }

    // AC-B16b: handle_client_export for unknown client fails
    #[test]
    fn cli_export_unknown_fails() {
        let registry = test_registry();
        let ctx = test_server_context();
        let err = handle_client_export(&registry, &ctx, "nonexistent", false, None);
        assert!(err.is_err());
    }

    // AC-B17: import_config_to reads TOML file
    #[test]
    fn cli_import_reads_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("client.toml");

        let toml_content = "[client]\nname = \"imported-client\"\n\n[server]\nendpoint = \"10.0.0.1:443\"\n";
        std::fs::write(&config_path, toml_content).expect("write config");

        let output_dir = dir.path().join("config");
        import_config_to(config_path.to_str().expect("path"), &output_dir).expect("import should succeed");

        let imported = output_dir.join(DEFAULT_CLIENT_CONFIG_FILENAME);
        assert!(imported.exists(), "imported config should exist");
        let content = std::fs::read_to_string(imported).expect("read imported");
        assert!(content.contains("imported-client"));
    }

    // AC-B18: import_config_to decodes prrr:// URL
    #[test]
    fn cli_import_decodes_url() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use flate2::Compression;
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let toml_content = "[client]\nname = \"url-client\"\n\n[server]\nendpoint = \"10.0.0.1:443\"\n";
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(toml_content.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&compressed);
        let url = format!("prrr://import?z={encoded}");

        let dir = tempfile::tempdir().expect("tempdir");
        let output_dir = dir.path().join("config");

        import_config_to(&url, &output_dir).expect("import URL should succeed");

        let imported = output_dir.join(DEFAULT_CLIENT_CONFIG_FILENAME);
        assert!(imported.exists(), "imported config should exist");
        let content = std::fs::read_to_string(imported).expect("read imported");
        assert!(content.contains("url-client"));
    }

    // AC-B18b: import_config_to fails for invalid TOML
    #[test]
    fn cli_import_invalid_toml_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("bad.toml");
        std::fs::write(&config_path, "{{{{not valid toml").expect("write");

        let output_dir = dir.path().join("config");
        let err = import_config_to(config_path.to_str().expect("path"), &output_dir);
        assert!(err.is_err(), "invalid TOML should fail");
    }
}
