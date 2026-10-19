# Security Hardening

This document describes the security hardening measures applied in F-017.

## Key Material Zeroization

All structs holding sensitive key material implement `Zeroize` or custom `Drop` impls that zero secret bytes when the struct is deallocated. This prevents key material from lingering in memory after use.

### Zeroized Types

| Type | Module | Secret Fields | Mechanism |
|------|--------|--------------|-----------|
| `SessionKeys` | `handshake::hybrid` | `tx_key`, `rx_key`, `header_key` | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| `EncryptedChannel` | `transport::encrypted_channel` | `tx_key`, `rx_key`, `rx_key_cache` | Custom `Drop` impl |
| `InitiatorState` | `crypto::hybrid_kex` | `kem_shared_secret` | Custom `Drop` impl |
| `KeyPair` | `handshake::noise_ik` | `private` (`Vec<u8>`) | Custom `Drop` impl |
| `KeyPair` | `crypto::x25519` | `secret` (`StaticSecret`) | x25519-dalek built-in zeroize |
| `KemKeyPair` | `crypto::hybrid_kex` | `dk` (`DecapsulationKey`) | ml-kem built-in zeroize |

### Pre-existing Zeroization

The following types already had zeroization via their underlying crate implementations:
- `x25519_dalek::StaticSecret` — zeroized on drop
- `x25519_dalek::SharedSecret` — zeroized via `DhOutput::to_bytes()`
- `ml_kem::DecapsulationKey` — zeroized by ml-kem crate

## Constant-Time Operations

All MAC and authentication tag comparisons use constant-time operations to prevent timing side-channel attacks:

| Location | Operation | Mechanism |
|----------|-----------|-----------|
| `crypto::aead` | AEAD tag verification | `chacha20poly1305` crate (uses `subtle` internally) |
| `obfuscation::probe_resist` | Auth token MAC verification | `subtle::ConstantTimeEq` |
| `handshake::noise_ik` | Noise message authentication | `snow` crate (constant-time internally) |

## Fuzzing

Fuzz targets exist in `fuzz/fuzz_targets/` for all parser and deserializer entry points that process untrusted input.

### Fuzz Targets

| Target | Module | Entry Point |
|--------|--------|-------------|
| `fuzz_encrypted_channel_recv` | `transport::encrypted_channel` | `EncryptedChannel::recv()` |
| `fuzz_varint_decode` | `transport::masque` | `varint_decode()` |
| `fuzz_deframe_datagram` | `transport::masque` | `deframe_datagram()` |
| `fuzz_traffic_unpad` | `obfuscation::traffic_morph` | `unpad()` |
| `fuzz_auth_token_validate` | `obfuscation::probe_resist` | `AuthToken::validate()` |
| `fuzz_aead_decrypt` | `crypto::aead` | `decrypt()` |

### Running Fuzz Targets

Fuzzing requires a nightly Rust toolchain and `cargo-fuzz`:

```bash
# Install cargo-fuzz (one time)
cargo install cargo-fuzz

# Run a specific fuzz target for 60 seconds
cd fuzz/
cargo +nightly fuzz run fuzz_wire_message -- -max_total_time=60

# Run with a maximum input length
cargo +nightly fuzz run fuzz_encrypted_channel_recv -- -max_len=2048 -max_total_time=60
```

## Benchmarks

Criterion benchmarks cover all critical crypto and transport operations.

### Benchmark Suites

| Suite | File | Operations |
|-------|------|------------|
| Crypto | `benches/crypto_benchmarks.rs` | AEAD encrypt/decrypt, X25519 DH/keygen, ML-KEM encap/decap, HKDF, BLAKE2s |
| Handshake | `benches/handshake_benchmarks.rs` | Noise IK full handshake, hybrid handshake, keygen |
| Transport | `benches/transport_benchmarks.rs` | EncryptedChannel send/recv, throughput |

### Running Benchmarks

```bash
# Run all benchmarks
make bench

# Run specific benchmark suite
cargo bench --bench crypto_benchmarks

# Quick mode (fewer iterations)
cargo bench -- --quick
```

## TLS Certificate Verification

The client supports two certificate verification modes controlled by the
`--insecure` CLI flag or `insecure_skip_verify` config option:

| Mode | Flag | Behavior |
|------|------|----------|
| Production (default) | `--insecure` absent | Verifies server certificate against Mozilla CA root store (`webpki-roots`) |
| Dev/Test | `--insecure` present | Accepts any certificate (including self-signed) |

When insecure mode is active, a warning is logged at startup:
`TLS certificate verification disabled (--insecure). Do NOT use in production.`

The verification is implemented in `src/transport/tls.rs::build_cert_verifier(insecure)` and
used by all three client config builders: `build_masque_client_config`,
`build_client_config` (QUIC), and `build_mimicked_client_config` (TLS mimicry).

## Server TLS Certificate Loading

The server supports loading CA-signed TLS certificates from PEM files via
`transport.tls_cert` and `transport.tls_key` config fields. This is critical
for DPI evasion — self-signed certificates are trivially detectable.

| Config | Behavior |
|--------|----------|
| `tls_cert` + `tls_key` set | Loads PEM certificate chain and private key from disk |
| Either field absent | Falls back to self-signed certificate generation (dev/test only) |

When using self-signed fallback, a warning is logged:
`no TLS certificate configured, generating self-signed (not recommended for production)`

The loading is implemented in `src/transport/tls.rs::load_pem_cert_and_key()` using
`rustls-pemfile`. The full certificate chain (including intermediates) is passed to
the server config builders, which is required for proper chain validation by clients.

## SNI Configuration

The client `--server-name` flag has no default value and must be explicitly set
via CLI or `[server].server_name` in the config file. This prevents the SNI/IP
mismatch that occurs when a generic placeholder domain (e.g., `"www.google.com"`)
is sent in the TLS ClientHello while connecting to a different server IP.

The `prrr client doctor` command checks SNI configuration:
- Warns if `server_name` is not configured
- Warns if `server_name` is `"www.google.com"` (legacy dangerous default)
- Warns if `server_name` doesn't look like a valid domain (no dot or contains whitespace)

The server `--server-name` defaults to `"localhost"` for dev/test self-signed
certificate generation. In production, set it to the server's actual domain.

## Dependency Security

- All dependencies are pinned to specific versions in `Cargo.toml`
- `cargo audit` should be run periodically to check for known vulnerabilities
- The `make lint` target includes `cargo audit` (requires `cargo-audit` installed)

### Installing cargo-audit

```bash
cargo install cargo-audit
cargo audit
```

## Unsafe Code Policy

The project enforces `#![deny(unsafe_code)]` globally via `Cargo.toml`:

```toml
[lints.rust]
unsafe_code = "deny"
```

No unsafe code is permitted without explicit justification and safety proof.
