# FRD-DPI008: ChaCha20 Obfuscation Core (Encrypt/Decrypt)

**Feature:** Step 1.2 — ChaCha20 Obfuscation Core
**Status:** Complete
**Created:** 2026-02-22
**Roadmap:** [specs/dpi-hardening-2/ROADMAP.md](../dpi-hardening-2/ROADMAP.md)
**Spec:** [specs/dpi-hardening-2/SPEC.MD](../dpi-hardening-2/SPEC.MD) — Section 2.3

## Overview

Implement the stateless PSK UDP obfuscation layer that wraps and unwraps UDP payloads using ChaCha20 stream cipher. This is a pure cryptographic module with no I/O — it takes a 256-bit PSK and a plaintext payload, generates a random 8-byte nonce, encrypts with ChaCha20, and returns `[nonce (8B)] + [ciphertext]`. The reverse operation strips the nonce and decrypts.

## Motivation

Standard QUIC/TLS packets have recognizable protocol signatures (initial byte patterns, version fields, connection IDs). DPI systems can identify and block QUIC traffic even on port 443. By applying ChaCha20 stream cipher with a random nonce to the entire UDP payload before it hits the wire, the traffic becomes indistinguishable from random noise. Since QUIC already provides authenticated encryption via TLS 1.3, the outer layer only needs confidentiality (no AEAD tag), minimizing per-packet overhead to just 8 bytes (nonce).

## Goals

1. Create `PskObfuscator` struct holding a 256-bit PSK
2. Implement `obfuscate()` — generates random 8-byte nonce, applies ChaCha20, returns `nonce || ciphertext`
3. Implement `deobfuscate()` — splits nonce from packet, decrypts, returns plaintext
4. Define `PskError` error type for PSK-specific failures
5. Register module in `src/obfuscation/mod.rs`

## Non-Goals

- Socket-level integration (Step 1.3 client, Step 1.4 server)
- Configuration wiring (already done in Step 1.1)
- Doctor diagnostic checks (Step 1.5)
- Performance benchmarks (will be added in Step 3.1)

## Wire Format

```text
[Nonce (8 bytes, random)] [Obfuscated QUIC Payload (N bytes)]
```

Total overhead: 8 bytes per packet.

ChaCha20 is a stream cipher — ciphertext length equals plaintext length (no expansion).

## Requirements

**FR-DPI008-01**: `PskObfuscator` SHALL be constructed from a 256-bit (32-byte) PSK.

**FR-DPI008-02**: `PskObfuscator::obfuscate()` SHALL generate a cryptographically random 8-byte nonce, apply ChaCha20 stream cipher keyed by the PSK, and return `nonce || ciphertext`.

**FR-DPI008-03**: `PskObfuscator::deobfuscate()` SHALL split the first 8 bytes as nonce, apply ChaCha20 decryption, and return the plaintext.

**FR-DPI008-04**: `deobfuscate()` SHALL reject packets shorter than 9 bytes (8-byte nonce + at least 1 byte payload) with `PskError::PacketTooShort`.

**FR-DPI008-05**: `deobfuscate(obfuscate(data))` SHALL equal `data` for any input (roundtrip invariant).

**FR-DPI008-06**: Two calls to `obfuscate()` with the same plaintext SHALL produce different ciphertexts (different random nonces).

**FR-DPI008-07**: `deobfuscate()` with a wrong PSK SHALL produce output that differs from the original plaintext.

**FR-DPI008-08**: ChaCha20 nonce construction SHALL use the 8-byte random nonce zero-padded to 12 bytes (ChaCha20 standard nonce size).

**NFR-DPI008-01**: Nonce generation SHALL use `rand::thread_rng()` (cryptographically secure).

**NFR-DPI008-02**: The module SHALL use the `chacha20` crate (stream cipher only, no AEAD tag overhead).

**NFR-DPI008-03**: The module SHALL have zero `unsafe` code.

## Acceptance Criteria

- [x] AC-1: `PskObfuscator::new()` accepts a 32-byte key
- [x] AC-2: `obfuscate()` returns `nonce (8B) || ciphertext` where ciphertext length equals plaintext length
- [x] AC-3: `deobfuscate(obfuscate(data)) == data` (roundtrip)
- [x] AC-4: Packets shorter than 9 bytes are rejected with `PskError::PacketTooShort`
- [x] AC-5: Different nonces produce different ciphertexts for the same plaintext
- [x] AC-6: Wrong PSK produces different output (not original plaintext)
- [x] AC-7: Module registered in `src/obfuscation/mod.rs`
- [x] AC-8: `make test` passes (652 tests: 599 lib + 23 integration + 30 bench)
- [x] AC-9: `make lint` clean

## Test Matrix

| ID | Type | Description |
|----|------|-------------|
| T-1 | Unit | Obfuscate returns nonce + ciphertext with correct lengths |
| T-2 | Unit | Deobfuscate roundtrip recovers original plaintext |
| T-3 | Unit | Packet too short (< 9 bytes) rejected |
| T-4 | Unit | Empty packet (0 bytes) rejected |
| T-5 | Unit | Exactly 8 bytes rejected (nonce only, no payload) |
| T-6 | Unit | Different nonces produce different ciphertexts |
| T-7 | Unit | Wrong PSK produces different decryption output |
| T-8 | Unit | Single-byte payload works (minimum valid case) |
| T-9 | Unit | Large payload (MTU-sized, 1280 bytes) roundtrip |
| T-10 | Property | Roundtrip for arbitrary payloads (proptest) |
| T-11 | Unit | Output is not plaintext (actually encrypted) |

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| `chacha20` crate API changes | Medium | Pin version, use stable trait-based API (`cipher` traits) |
| Nonce collision (8-byte random) | Very Low | 2^64 space; birthday bound at ~2^32 packets (~4 billion) per key |
| Stream cipher without authentication | Accepted | QUIC provides authentication; outer layer only needs confidentiality |

## Rollback

- Remove `src/obfuscation/psk_udp.rs`
- Remove module registration from `src/obfuscation/mod.rs`
- Remove `chacha20` from `Cargo.toml`

## Implementation

### Files Created
- `src/obfuscation/psk_udp.rs` — `PskObfuscator`, `PskError`, `obfuscate()`, `deobfuscate()` (+15 unit tests)

### Files Modified
- `src/obfuscation/mod.rs` — registered `psk_udp` module
- `Cargo.toml` — added `chacha20 = "0.9.1"` direct dependency
- `docs/obfuscation.md` — added wire format, usage examples, API reference, security notes

## Traceability

- **Spec**: `specs/dpi-hardening-2/SPEC.MD` Section 2.2–2.3
- **Roadmap**: `specs/dpi-hardening-2/ROADMAP.md` Step 1.2
- **Depends on**: FRD-DPI007 (PSK key generation and config)
