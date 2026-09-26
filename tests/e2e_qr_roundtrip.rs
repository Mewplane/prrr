//! End-to-end tests for the QR config distribution pipeline.
//!
//! Validates wire-format compatibility: server generates config → compress →
//! base64url → QR URL → decompress → parse TOML → verify fields match.
//!
//! These tests enforce that the config format is compatible between `prrr`
//! server and `prrr-mobile` parser WITHOUT any patching or transformation.
//! The only allowed difference: `private_key_path` (CLI) vs `private_key`
//! (mobile) — the server must support both via `generate_client_config`.

use std::io::{Read, Write};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use prrr::{
    distribution::{ServerContext, decode_import_url, generate_client_config, generate_qr_svg},
    registry::ClientRegistry,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MLKEM768_EK_LEN: usize = 1184;
const X25519_KEY_LEN: usize = 32;
const IMPORT_URL_PREFIX: &str = "prrr://import?z=";

/// Multi-frame chunk size (must match JS `MAX_CHUNK_CHARS` and Kotlin `FrameCollector`).
const MULTI_FRAME_MAX_CHUNK: usize = 300;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_server_context() -> ServerContext {
    ServerContext {
        endpoint: "vpn.example.com:443".to_string(),
        server_name: "vpn.example.com".to_string(),
        noise_public_key: [0xAA; X25519_KEY_LEN],
        kem_public_key: vec![0x42; MLKEM768_EK_LEN],
        dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        mtu: 1100,
        transport_protocol: "masque".to_string(),
    }
}

fn test_private_key() -> [u8; 32] {
    [0xBB; 32]
}

fn test_registry_and_record() -> (ClientRegistry, prrr::registry::ClientRecord) {
    let mut registry = ClientRegistry::new("10.66.66.0/24").expect("valid subnet");
    let record = registry.add("e2e-test-client", [0xCC; 32], None).expect("add client");
    (registry, record)
}

fn deflate_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn deflate_decompress(compressed: &[u8]) -> String {
    let mut decoder = DeflateDecoder::new(compressed);
    let mut result = String::new();
    decoder.read_to_string(&mut result).unwrap();
    result
}

/// Build multi-frame URLs from a base64url payload (mirrors JS buildMultiFrameUrls).
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
        .map(|(i, chunk)| format!("prrr://import?f={}.{total}&z={chunk}", i + 1))
        .collect()
}

/// Reassemble multi-frame URLs back into a single-frame URL (mirrors Kotlin FrameCollector).
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

// ---------------------------------------------------------------------------
// Wire format compatibility tests
// ---------------------------------------------------------------------------

/// Server config with inline private_key is directly parseable by mobile
/// WITHOUT any patching. This is the core compatibility test.
#[test]
fn e2e_mobile_config_is_wire_compatible() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();
    let private_key = test_private_key();

    // Generate config WITH private key (mobile path)
    let config_toml = generate_client_config(&ctx, &record, Some(&private_key)).expect("generate mobile config");

    // Verify it has private_key (not private_key_path)
    assert!(
        config_toml.contains("private_key = \""),
        "mobile config must have inline private_key"
    );
    assert!(
        !config_toml.contains("private_key_path"),
        "mobile config must NOT have private_key_path"
    );

    // Verify transport_protocol is in [interface] (not separate [transport] section)
    assert!(
        config_toml.contains("transport_protocol = \"masque\""),
        "must have transport_protocol in [interface]"
    );
    assert!(!config_toml.contains("[transport]"), "must NOT have separate [transport] section");

    // Compress and encode the way the QR pipeline does
    let compressed = deflate_compress(config_toml.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(&compressed);
    let url = format!("{IMPORT_URL_PREFIX}{encoded}");

    // Decompress and parse the way prrr-mobile does
    let decoded_compressed = URL_SAFE_NO_PAD.decode(&encoded).expect("base64 decode");
    let decompressed = deflate_decompress(&decoded_compressed);
    let parsed: toml::Value = toml::from_str(&decompressed).expect("parse TOML");

    // Verify all fields the mobile parser requires are present
    assert_eq!(parsed["client"]["name"].as_str().unwrap(), "e2e-test-client");
    assert_eq!(parsed["server"]["endpoint"].as_str().unwrap(), "vpn.example.com:443");
    assert!(parsed["server"]["public_key"].as_str().is_some());
    assert!(parsed["server"]["pq_public_key"].as_str().is_some());
    assert!(parsed["interface"]["private_key"].as_str().is_some());
    assert!(parsed["interface"]["address"].as_str().is_some());
    assert!(parsed["interface"]["dns"].as_array().is_some());
    assert!(parsed["interface"]["mtu"].as_integer().is_some());
    assert_eq!(parsed["interface"]["transport_protocol"].as_str().unwrap(), "masque");

    // Verify key lengths after base64 decode
    let noise_key = STANDARD.decode(parsed["server"]["public_key"].as_str().unwrap()).unwrap();
    assert_eq!(noise_key.len(), X25519_KEY_LEN);
    let kem_key = STANDARD.decode(parsed["server"]["pq_public_key"].as_str().unwrap()).unwrap();
    assert_eq!(kem_key.len(), MLKEM768_EK_LEN);
    let priv_key = STANDARD.decode(parsed["interface"]["private_key"].as_str().unwrap()).unwrap();
    assert_eq!(priv_key.len(), X25519_KEY_LEN);

    // Verify URL is decodable via server's decode_import_url
    let server_decoded = decode_import_url(&url).expect("server decode_import_url");
    assert_eq!(server_decoded, config_toml);
}

/// CLI config (no inline private key) uses private_key_path instead.
#[test]
fn e2e_cli_config_uses_private_key_path() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();

    let config_toml = generate_client_config(&ctx, &record, None).expect("generate CLI config");

    assert!(
        config_toml.contains("private_key_path = \""),
        "CLI config must have private_key_path"
    );
    assert!(
        !config_toml.contains("\nprivate_key = \""),
        "CLI config must NOT have inline private_key"
    );

    // Transport protocol must still be in [interface]
    assert!(config_toml.contains("transport_protocol = \"masque\""));
}

/// Default transport protocol is masque.
#[test]
fn e2e_default_transport_is_masque() {
    assert_eq!(
        prrr::config::DEFAULT_TRANSPORT_PROTOCOL,
        "masque",
        "default transport must be masque"
    );
}

// ---------------------------------------------------------------------------
// QR encoding tests
// ---------------------------------------------------------------------------

#[test]
fn e2e_server_qr_generation_and_decode_roundtrip() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();

    let config_toml = generate_client_config(&ctx, &record, None).expect("generate config");
    let svg = generate_qr_svg(&config_toml).expect("generate QR SVG");

    assert!(svg.contains("<svg"), "output must be valid SVG");

    let compressed = deflate_compress(config_toml.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(&compressed);
    let url = format!("{IMPORT_URL_PREFIX}{encoded}");

    let decoded = decode_import_url(&url).expect("decode URL");
    assert_eq!(decoded, config_toml, "round-trip decode must match original config");
}

#[test]
fn e2e_compressed_payload_is_url_safe() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();

    let config_toml = generate_client_config(&ctx, &record, Some(&test_private_key())).expect("generate config");

    let compressed = deflate_compress(config_toml.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(&compressed);

    assert!(!encoded.contains('+'), "base64url must not contain '+'");
    assert!(!encoded.contains('/'), "base64url must not contain '/'");
    assert!(!encoded.contains('='), "base64url must not contain padding '='");
}

#[test]
fn e2e_decode_rejects_wrong_prefix() {
    assert!(decode_import_url("https://example.com/malicious").is_err());
    assert!(decode_import_url("prrr://import?config=dGVzdA").is_err());
}

#[test]
fn e2e_decode_rejects_corrupted_compressed_data() {
    let url = format!("{IMPORT_URL_PREFIX}SGVsbG8gV29ybGQ");
    assert!(decode_import_url(&url).is_err());
}

// ---------------------------------------------------------------------------
// Multi-frame roundtrip tests
// ---------------------------------------------------------------------------

#[test]
fn e2e_multiframe_split_and_reassemble_roundtrip() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();

    let config_toml = generate_client_config(&ctx, &record, Some(&test_private_key())).expect("generate config");

    let compressed = deflate_compress(config_toml.as_bytes());
    let payload = URL_SAFE_NO_PAD.encode(&compressed);

    // Payload with ML-KEM key should be large enough to need multiple frames
    assert!(
        payload.len() > MULTI_FRAME_MAX_CHUNK,
        "payload ({} chars) should exceed chunk size ({MULTI_FRAME_MAX_CHUNK})",
        payload.len()
    );

    let frames = build_multiframe_urls(&payload);
    assert!(frames.len() > 1, "should produce multiple frames");

    // Each frame should be small enough for QR scanning
    for (i, frame) in frames.iter().enumerate() {
        assert!(frame.len() < 400, "frame {} too large: {} chars", i + 1, frame.len());
    }

    // Reassemble and verify matches original URL
    let reassembled = reassemble_multiframe(&frames);
    let expected_url = format!("{IMPORT_URL_PREFIX}{payload}");
    assert_eq!(reassembled, expected_url, "reassembled URL must match original");

    // Verify reassembled URL decodes to original config
    let decoded = decode_import_url(&reassembled).expect("decode reassembled");
    assert_eq!(decoded, config_toml);
}

#[test]
fn e2e_multiframe_reversed_order_reassembles_correctly() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();

    let config_toml = generate_client_config(&ctx, &record, Some(&test_private_key())).expect("generate config");

    let compressed = deflate_compress(config_toml.as_bytes());
    let payload = URL_SAFE_NO_PAD.encode(&compressed);

    let mut frames = build_multiframe_urls(&payload);
    frames.reverse();

    let reassembled = reassemble_multiframe(&frames);
    let decoded = decode_import_url(&reassembled).expect("decode reversed");
    assert_eq!(decoded, config_toml);
}

#[test]
fn e2e_different_clients_produce_different_qr_urls() {
    let ctx = test_server_context();
    let mut registry = ClientRegistry::new("10.66.66.0/24").expect("valid subnet");

    let record_a = registry.add("client-alice", [0xAA; 32], None).expect("add alice");
    let record_b = registry.add("client-bob", [0xBB; 32], None).expect("add bob");

    let config_a = generate_client_config(&ctx, &record_a, None).expect("config alice");
    let config_b = generate_client_config(&ctx, &record_b, None).expect("config bob");

    let url_a = format!(
        "{IMPORT_URL_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(deflate_compress(config_a.as_bytes()))
    );
    let url_b = format!(
        "{IMPORT_URL_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(deflate_compress(config_b.as_bytes()))
    );

    assert_ne!(url_a, url_b);
    assert_eq!(decode_import_url(&url_a).unwrap(), config_a);
    assert_eq!(decode_import_url(&url_b).unwrap(), config_b);
}

// ---------------------------------------------------------------------------
// Cross-file consistency tests
// ---------------------------------------------------------------------------

/// FrameCollector URL prefix constants must match server-side constants.
#[test]
fn e2e_frame_collector_prefix_matches_server() {
    let collector_src = std::fs::read_to_string("prrr-android/app/src/main/kotlin/com/prrr/vpn/android/scanner/FrameCollector.kt")
        .expect("read FrameCollector.kt");

    assert!(
        collector_src.contains("prrr://import?z="),
        "FrameCollector must use same single-frame prefix as server"
    );
    assert!(
        collector_src.contains("prrr://import?f="),
        "FrameCollector must use same multi-frame prefix as server"
    );
}

/// QRCodeAnalyzer uses ZXing (not ML Kit) for emulator compatibility.
#[test]
fn e2e_scanner_uses_zxing() {
    let analyzer = std::fs::read_to_string("prrr-android/app/src/main/kotlin/com/prrr/vpn/android/scanner/QRCodeAnalyzer.kt")
        .expect("read QRCodeAnalyzer.kt");

    assert!(analyzer.contains("com.google.zxing"), "QRCodeAnalyzer must use ZXing");
    assert!(analyzer.contains("QR_CODE"), "QRCodeAnalyzer must filter for QR_CODE format");
}

// ---------------------------------------------------------------------------
// CLI import end-to-end tests (items 1-3)
// ---------------------------------------------------------------------------

/// `prrr client import <url>` — generate config, compress to URL, import, verify saved file.
#[test]
fn e2e_cli_import_from_compressed_url() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();

    let config_toml = generate_client_config(&ctx, &record, Some(&test_private_key())).expect("generate config");

    // Compress the way the QR pipeline does
    let compressed = deflate_compress(config_toml.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(&compressed);
    let url = format!("{IMPORT_URL_PREFIX}{encoded}");

    // Import to a temp directory
    let dir = tempfile::tempdir().expect("tempdir");
    prrr::cli::import_config_to(&url, dir.path()).expect("import from URL");

    // Verify the saved file matches the original config
    let saved = std::fs::read_to_string(dir.path().join("client.toml")).expect("read saved");
    assert_eq!(saved, config_toml, "imported config must match original");
}

/// `prrr client import <file>` — save config to file, import from file, verify.
#[test]
fn e2e_cli_import_from_file() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();

    let config_toml = generate_client_config(&ctx, &record, Some(&test_private_key())).expect("generate config");

    let dir = tempfile::tempdir().expect("tempdir");
    let source_path = dir.path().join("source.toml");
    std::fs::write(&source_path, &config_toml).expect("write source");

    let output_dir = dir.path().join("imported");
    prrr::cli::import_config_to(source_path.to_str().unwrap(), &output_dir).expect("import from file");

    let saved = std::fs::read_to_string(output_dir.join("client.toml")).expect("read saved");
    assert_eq!(saved, config_toml, "imported config must match original");
}

/// `prrr server client add --qr` — generates both config and QR SVG.
#[test]
fn e2e_cli_add_with_qr_generates_svg() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();

    let config_toml = generate_client_config(&ctx, &record, Some(&test_private_key())).expect("generate config");

    let svg = generate_qr_svg(&config_toml).expect("generate QR SVG");
    assert!(svg.contains("<svg"), "must produce valid SVG");
    assert!(svg.contains("</svg>"), "SVG must be complete");

    // The QR encodes the compressed config — verify round-trip
    let compressed = deflate_compress(config_toml.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(&compressed);
    let url = format!("{IMPORT_URL_PREFIX}{encoded}");
    let decoded = decode_import_url(&url).expect("decode");
    assert_eq!(decoded, config_toml);
}

// ---------------------------------------------------------------------------
// Web UI patch simulation (item 4)
// ---------------------------------------------------------------------------

/// Simulates web UI `patchConfigForMobile`: takes a server config (with
/// `private_key_path`), replaces it with inline `private_key`. The result
/// must be identical to `generate_client_config(Some(key))`.
#[test]
fn e2e_web_ui_patch_produces_same_config_as_direct_generation() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();
    let private_key = test_private_key();

    // Server config (what the API returns) — has private_key_path
    let server_config = generate_client_config(&ctx, &record, None).expect("generate server config");
    assert!(
        server_config.contains("private_key_path"),
        "server config must have private_key_path"
    );

    // Direct mobile config — has inline private_key
    let mobile_config = generate_client_config(&ctx, &record, Some(&private_key)).expect("generate mobile config");
    assert!(
        mobile_config.contains("private_key = \""),
        "mobile config must have inline private_key"
    );

    // Simulate JS patchConfigForMobile: replace private_key_path line with private_key line
    // (JS split("\n").join("\n") preserves the trailing newline via the final empty element)
    let key_b64 = STANDARD.encode(private_key);
    let patched: String = server_config
        .split('\n')
        .map(|line| {
            if line.starts_with("private_key_path") {
                format!("private_key = \"{key_b64}\"")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert_eq!(patched, mobile_config, "JS-patched config must match direct mobile generation");
}

// ---------------------------------------------------------------------------
// Cross-crate: prrr-mobile parses server-generated config (items 5+6)
// ---------------------------------------------------------------------------

/// Run the actual JavaScript patchConfigForMobile and buildMultiFrameUrls
/// functions extracted from assets/index.html via Node.js.
#[test]
fn e2e_actual_js_patch_and_multiframe_functions() {
    let output = std::process::Command::new("node")
        .arg("tests/js_patch_test.js")
        .output()
        .expect("node must be available to test JS functions");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "JS tests failed (exit {}):\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code().unwrap_or(-1)
    );
    assert!(
        stdout.contains("JS_TESTS_PASSED"),
        "JS tests did not produce pass marker:\nstdout: {stdout}\nstderr: {stderr}"
    );
}

/// `prrr_mobile::parse_qr_config` successfully parses a config generated by
/// `prrr::distribution::generate_client_config` — the actual Rust code path
/// used by the Android app via UniFFI.
#[test]
fn e2e_prrr_mobile_parses_server_generated_config() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();
    let private_key = test_private_key();

    let config_toml = generate_client_config(&ctx, &record, Some(&private_key)).expect("generate config");

    // Compress the way the QR pipeline does
    let compressed = deflate_compress(config_toml.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(&compressed);
    let url = format!("{IMPORT_URL_PREFIX}{encoded}");

    // Call the actual prrr-mobile parser (same code path as Android UniFFI)
    let vpn_config = prrr_mobile::parse_qr_config(url).expect("prrr-mobile must parse server config");

    // Verify all fields match
    assert_eq!(vpn_config.client_name, record.name);
    assert_eq!(vpn_config.server_endpoint, ctx.endpoint);
    assert_eq!(vpn_config.mtu, ctx.mtu);
    assert_eq!(vpn_config.server_public_key.len(), 32);
    assert_eq!(vpn_config.server_pq_public_key.len(), MLKEM768_EK_LEN);
    assert_eq!(vpn_config.client_private_key.len(), 32);
    assert_eq!(vpn_config.client_private_key, private_key.to_vec());
    assert_eq!(vpn_config.dns_servers, ctx.dns_servers);
    assert_eq!(vpn_config.transport_protocol.as_deref(), Some("masque"));
}

/// Multi-frame roundtrip through the actual `prrr_mobile::parse_qr_config`.
#[test]
fn e2e_prrr_mobile_parses_multiframe_reassembled_config() {
    let ctx = test_server_context();
    let (_registry, record) = test_registry_and_record();
    let private_key = test_private_key();

    let config_toml = generate_client_config(&ctx, &record, Some(&private_key)).expect("generate config");

    let compressed = deflate_compress(config_toml.as_bytes());
    let payload = URL_SAFE_NO_PAD.encode(&compressed);
    let frames = build_multiframe_urls(&payload);
    assert!(frames.len() > 1, "should need multiple frames");

    // Reassemble (simulates Kotlin FrameCollector)
    let reassembled = reassemble_multiframe(&frames);

    // Parse with actual prrr-mobile code
    let vpn_config = prrr_mobile::parse_qr_config(reassembled).expect("prrr-mobile must parse reassembled multiframe config");

    assert_eq!(vpn_config.client_name, record.name);
    assert_eq!(vpn_config.server_endpoint, ctx.endpoint);
    assert_eq!(vpn_config.client_private_key, private_key.to_vec());
}
