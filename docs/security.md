# Security Hardening

This document describes the security hardening measures applied in F-017.

## Key Material Zeroization

All structs holding sensitive key material implement `Zeroize` or custom `Drop` impls that zero secret bytes when the struct is deallocated. This prevents key material from lingering in memory after use.

### Zeroized Types

| Type | Module | Secret Fields | Mechanism |
|------|--------|--------------|-----------|
| `SessionKeys` | `handshake::hybrid` | `tx_key`, `rx_key`, `header_key` | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| `EncryptedChannel` | `transport::encrypted_channel` | `tx_key`, `rx_key`, `rx_key_cache` | Custom `Drop` impl |
| `RatchetState` | `messaging::ratchet` | `root_key`, `send_chain_key`, `recv_chain_key`, `skipped_keys` | Custom `Drop` impl |
| `InitiatorState` | `crypto::hybrid_kex` | `kem_shared_secret` | Custom `Drop` impl |
| `SessionInitResult` | `messaging::pqxdh` | `shared_secret` | Custom `Drop` impl |
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
| `messaging::keys` | Prekey signature verification | `subtle::ConstantTimeEq` |
| `obfuscation::probe_resist` | Auth token MAC verification | `subtle::ConstantTimeEq` |
| `handshake::noise_ik` | Noise message authentication | `snow` crate (constant-time internally) |

## Fuzzing

Fuzz targets exist in `fuzz/fuzz_targets/` for all parser and deserializer entry points that process untrusted input.

### Fuzz Targets

| Target | Module | Entry Point |
|--------|--------|-------------|
| `fuzz_wire_message` | `messaging::types` | `WireMessage::from_bytes()` |
| `fuzz_encrypted_envelope` | `messaging::types` | `EncryptedEnvelope::from_bytes()` |
| `fuzz_message_header` | `messaging::ratchet` | `MessageHeader::from_bytes()` |
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
| Messaging | `benches/messaging_benchmarks.rs` | Double Ratchet encrypt/decrypt, PQXDH initiate/respond |

### Running Benchmarks

```bash
# Run all benchmarks
make bench

# Run specific benchmark suite
cargo bench --bench crypto_benchmarks

# Quick mode (fewer iterations)
cargo bench -- --quick
```

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
