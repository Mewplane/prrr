# FRD-M002: UniFFI Interface Definition

**Feature:** Feature 1.2 - UniFFI Interface Definition  
**Status:** Complete  
**Created:** 2026-02-22  
**Completed:** 2026-02-22  
**Predecessor:** FRD-M001 (Mobile Workspace & Build Infrastructure)

## Overview

Define the Foreign Function Interface (FFI) boundary between Rust and mobile platforms (Swift/Kotlin) using Mozilla's UniFFI framework. This creates type-safe bindings for configuration parsing and basic error types.

## Motivation

Mobile applications written in Swift (iOS) and Kotlin (Android) need to call Rust code from the prrr-mobile library. Manual FFI is error-prone and maintenance-heavy. UniFFI automatically generates type-safe bindings from a simple Interface Definition Language (UDL) file, ensuring consistency across platforms.

This FRD implements the **minimal viable API** for Feature 1.2:
- Configuration parsing from QR codes  
- Configuration validation
- Error handling

Connection management will be added in Feature 1.4.

## Goals

1. Add UniFFI dependencies to prrr-mobile
2. Create UDL file defining mobile API surface
3. Implement Rust functions matching UDL
4. Generate Swift and Kotlin bindings
5. Verify bindings compile and are usable

## Non-Goals

- VPN connection management (Feature 1.4)
- Statistics/state tracking (Feature 1.4)  
- UI integration (Phases 2 & 3)
- Performance optimization

## Requirements

### Functional Requirements

**FR-M002-01**: Add UniFFI 0.28+ as dependency with build support

**FR-M002-02**: Create `mobile.udl` defining:
- Namespace `prrr_mobile` with free functions
- `VpnConfig` dictionary (struct-like)
- `MobileError` error enum
- `parse_qr_config()` function
- `validate_config()` function

**FR-M002-03**: Implement `parse_qr_config()` by reusing existing `decode_import_url()` from `src/distribution.rs`

**FR-M002-04**: Implement `validate_config()` checking:
- `server_endpoint` is non-empty
- Keys are correct lengths (32 bytes for Noise, 1184 for ML-KEM-768)
- `assigned_ip` is valid CIDR notation
- `dns_servers` array is non-empty
- `mtu` is in valid range (1280-1500)

**FR-M002-05**: Generate Swift bindings via `uniffi-bindgen`

**FR-M002-06**: Generate Kotlin bindings via `uniffi-bindgen`

### Non-Functional Requirements

**NFR-M002-01**: UniFFI scaffolding SHALL compile without warnings

**NFR-M002-02**: Generated bindings SHALL be human-readable

**NFR-M002-03**: Parse/validate functions SHALL have <1ms latency

## Design

### UniFFI Version

Using UniFFI **0.28.x** (latest stable as of 2026):
- Mature error handling with `[Error]` attribute
- Dictionary types for structs
- Good Swift/Kotlin support

### UDL Interface Design

```webidl
// prrr-mobile/src/mobile.udl

namespace prrr_mobile {
  /// Parse VPN configuration from QR code data
  ///
  /// Decodes a `prrr://import?config=<base64>` URL and parses the TOML config.
  [Throws=MobileError]
  VpnConfig parse_qr_config(string qr_data);
  
  /// Validate VPN configuration
  ///
  /// Checks that all required fields are present and valid.
  [Throws=MobileError]
  void validate_config(VpnConfig config);
};

/// VPN configuration for mobile clients
dictionary VpnConfig {
  string client_name;
  string server_endpoint;
  sequence<u8> server_public_key;
  sequence<u8> server_pq_public_key;
  sequence<u8> client_private_key;
  string assigned_ip;
  sequence<string> dns_servers;
  u16 mtu;
};

/// Errors from mobile operations
[Error]
enum MobileError {
  /// Invalid configuration data
  InvalidConfig(string reason),
  /// Connection failed
  ConnectionFailed(string reason),
  /// Handshake failed  
  HandshakeFailed(string reason),
  /// Network error
  NetworkError(string reason),
  /// Not connected
  NotConnected,
};
```

### Module Structure

```
prrr-mobile/
├── src/
│   ├── lib.rs           # Module exports + uniffi scaffolding
│   ├── mobile.udl       # UniFFI interface definition
│   ├── config.rs        # VpnConfig + parse/validate logic
│   └── error.rs         # MobileError type
├── build.rs             # UniFFI build script
└── Cargo.toml           # Dependencies
```

### Implementation Strategy

**Reuse Over Reinvention:**
- `parse_qr_config()` delegates to existing `prrr::distribution::decode_import_url()`
- TOML parsing reuses `toml` crate (already in workspace)
- No new crypto/network code in this feature

**Type Mapping:**
- Rust `Vec<u8>` ↔ Swift `[UInt8]` ↔ Kotlin `List<UByte>`
- Rust `String` ↔ Swift `String` ↔ Kotlin `String`
- Rust `u16` ↔ Swift `UInt16` ↔ Kotlin `UShort`

## Acceptance Criteria

**AC-M002-01**: `cargo build -p prrr-mobile` succeeds with UniFFI dependencies

**AC-M002-02**: `mobile.udl` compiles without errors

**AC-M002-03**: `uniffi-bindgen generate ... --language swift` produces valid Swift code

**AC-M002-04**: `uniffi-bindgen generate ... --language kotlin` produces valid Kotlin code

**AC-M002-05**: Rust unit tests verify `parse_qr_config()` decodes valid QR data

**AC-M002-06**: Rust unit tests verify `validate_config()` rejects invalid configs

**AC-M002-07**: Generated bindings include doc comments from UDL

**AC-M002-08**: Zero clippy warnings in prrr-mobile

## Testing Strategy

### Unit Tests (Rust)

**Test 1: Valid QR Parse**
```rust
#[test]
fn test_parse_valid_qr_config() {
    let config_toml = r#"
        [client]
        name = "test"
        [server]
        endpoint = "vpn.example.com:443"
        public_key = "..."
        pq_public_key = "..."
        [interface]
        private_key = "..."
        address = "10.66.66.2/32"
        dns = ["1.1.1.1"]
        mtu = 1280
    "#;
    let encoded = base64::URL_SAFE_NO_PAD.encode(config_toml);
    let qr_data = format!("prrr://import?config={}", encoded);
    
    let config = parse_qr_config(qr_data).unwrap();
    assert_eq!(config.client_name, "test");
}
```

**Test 2: Invalid Base64**
```rust
#[test]
fn test_parse_invalid_base64() {
    let result = parse_qr_config("prrr://import?config=!!!invalid!!!".to_string());
    assert!(matches!(result, Err(MobileError::InvalidConfig(_))));
}
```

**Test 3: Invalid TOML**
```rust
#[test]
fn test_parse_invalid_toml() {
    let encoded = base64::URL_SAFE_NO_PAD.encode(b"not valid toml {{{");
    let qr_data = format!("prrr://import?config={}", encoded);
    
    let result = parse_qr_config(qr_data);
    assert!(matches!(result, Err(MobileError::InvalidConfig(_))));
}
```

**Test 4: Validate Missing Endpoint**
```rust
#[test]
fn test_validate_missing_endpoint() {
    let config = VpnConfig {
        server_endpoint: "".to_string(),
        // ... other fields
    };
    let result = validate_config(config);
    assert!(matches!(result, Err(MobileError::InvalidConfig(_))));
}
```

**Test 5: Validate Invalid Key Length**
```rust
#[test]
fn test_validate_invalid_key_length() {
    let config = VpnConfig {
        server_public_key: vec![0u8; 16], // Should be 32
        // ... other fields
    };
    let result = validate_config(config);
    assert!(matches!(result, Err(MobileError::InvalidConfig(_))));
}
```

### Binding Generation Tests

```bash
# Swift
uniffi-bindgen generate src/mobile.udl --language swift --out-dir bindings/swift
# Verify: bindings/swift/prrr_mobile.swift exists and compiles

# Kotlin
uniffi-bindgen generate src/mobile.udl --language kotlin --out-dir bindings/kotlin
# Verify: bindings/kotlin/prrr_mobile.kt exists and compiles
```

### Coverage Target

- Config parsing: 100%
- Config validation: 100%
- Error handling: 100%
- Overall: >95%

## Dependencies

- **UniFFI**: 0.28.x
- **Base64**: 0.22.x (already in workspace)
- **TOML**: 1.0.x (already in workspace)
- **Serde**: 1.x (already in workspace)

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| UniFFI version incompatibility | Medium | Pin to 0.28.x, test bindings |
| Generated bindings don't compile | High | Add binding generation to CI |
| Key length constants wrong | High | Reuse constants from existing crypto module |

## Implementation Checklist

- [x] Step 1-3: Read docs, take roadmap item
- [x] Step 4: Write this FRD
- [x] Step 5: Re-read FRD
- [x] Step 6: Write tests (parse, validate, errors) - 14 tests, 100% pass
- [x] Step 7: Implement (UDL, config.rs, error.rs)
- [x] Step 8: cargo clippy -p prrr-mobile -- -D warnings - Clean
- [x] Step 9: make lint - Clean
- [x] Step 10: Fix warnings - N/A (no warnings)
- [x] Step 11: Iterate until tests pass - All tests pass
- [x] Step 12: (No profiling needed)
- [x] Step 13: Close roadmap item - Marked complete in ROADMAP.md
- [x] Step 14: Update docs/ - Created docs/mobile-api.md
- [x] Step 15: Update AGENTS.md (if needed) - N/A (no changes to agent instructions)
- [x] Step 16: Add traceability links - Added below

## Traceability

**Roadmap**: [specs/mobile-app/ROADMAP.md](../mobile-app/ROADMAP.md#feature-12-uniffi-interface-definition-) - Feature 1.2 ✅  
**Predecessor**: FRD-M001 (Mobile Workspace)  
**Successor**: FRD-M003 (QR Code Parsing - Feature 1.3) - Not yet implemented

**Implementation**:
- [x] [prrr-mobile/Cargo.toml](../../prrr-mobile/Cargo.toml) - UniFFI 0.28, thiserror, base64, serde, toml
- [x] [prrr-mobile/build.rs](../../prrr-mobile/build.rs) - UniFFI scaffolding generation
- [x] [prrr-mobile/src/mobile.udl](../../prrr-mobile/src/mobile.udl) - Interface definition
- [x] [prrr-mobile/src/lib.rs](../../prrr-mobile/src/lib.rs) - Module exports + scaffolding
- [x] [prrr-mobile/src/config.rs](../../prrr-mobile/src/config.rs) - VpnConfig + parse_qr_config() + validate_config()
- [x] [prrr-mobile/src/error.rs](../../prrr-mobile/src/error.rs) - MobileError type
- [x] [scripts/generate-bindings.sh](../../scripts/generate-bindings.sh) - Binding generation for Swift/Kotlin
- [x] [docs/mobile-api.md](../../docs/mobile-api.md) - API documentation

**Tests** (14 total, 100% pass):
- `test_parse_valid_qr_config_minimal` - [config.rs:240](../../prrr-mobile/src/config.rs#L240)
- `test_parse_invalid_prefix` - [config.rs:268](../../prrr-mobile/src/config.rs#L268)
- `test_parse_invalid_base64` - [config.rs:277](../../prrr-mobile/src/config.rs#L277)
- `test_parse_invalid_toml` - [config.rs:286](../../prrr-mobile/src/config.rs#L286)
- `test_parse_missing_client_name` - [config.rs:297](../../prrr-mobile/src/config.rs#L297)
- `test_parse_missing_server_section` - [config.rs:324](../../prrr-mobile/src/config.rs#L324)
- `test_validate_empty_endpoint` - [config.rs:342](../../prrr-mobile/src/config.rs#L342)
- `test_validate_invalid_key_length` - [config.rs:360](../../prrr-mobile/src/config.rs#L360)
- `test_validate_invalid_pq_key_length` - [config.rs:378](../../prrr-mobile/src/config.rs#L378)
- `test_validate_missing_cidr` - [config.rs:396](../../prrr-mobile/src/config.rs#L396)
- `test_validate_empty_dns` - [config.rs:414](../../prrr-mobile/src/config.rs#L414)
- `test_validate_invalid_mtu` - [config.rs:432](../../prrr-mobile/src/config.rs#L432)
- `test_validate_valid_config` - [config.rs:450](../../prrr-mobile/src/config.rs#L450)
- `test_version_exists` - [lib.rs:30](../../prrr-mobile/src/lib.rs#L30)

## References

- [UniFFI User Guide](https://mozilla.github.io/uniffi-rs/)
- [UniFFI Enums](https://mozilla.github.io/uniffi-rs/latest/udl/enumerations.html)
- [UniFFI Errors](https://mozilla.github.io/uniffi-rs/latest/udl/errors.html)
- [Swift Bindings](https://mozilla.github.io/uniffi-rs/latest/swift/overview.html)
- Existing: `src/distribution.rs` (QR decode logic)
- Existing: `src/config.rs` (TOML parsing)
