# FRD-DPI007: PSK Key Generation and Configuration

**Feature:** Step 1.1 — PSK Key Generation and Configuration
**Status:** Complete
**Created:** 2026-02-22
**Roadmap:** [specs/dpi-hardening-2/ROADMAP.md](../dpi-hardening-2/ROADMAP.md)
**Spec:** [specs/dpi-hardening-2/SPEC.MD](../dpi-hardening-2/SPEC.MD) — Section 2

## Overview

Add Pre-Shared Key (PSK) support to the configuration and key management layers. When PSK obfuscation is enabled on the server, a 256-bit obfuscation key is generated per-client during `prrr server client add`, stored in the SQLite registry, and included in exported client configurations. This is the foundational data-plane step for the PSK UDP obfuscation feature (DPI Hardening Phase 2).

## Motivation

Standard QUIC/TLS traffic has recognizable protocol signatures that advanced DPI systems can detect. PSK obfuscation wraps QUIC packets in a ChaCha20 stream cipher layer, making them indistinguishable from random noise. Before the crypto layer can be implemented (Step 1.2), the PSK must be generated, stored, and distributed through the existing config and registry infrastructure.

## Goals

1. Add `psk_obfuscation` and `obfuscation_key` fields to server `ObfuscationSection`
2. Add `psk_obfuscation` and `obfuscation_key` fields to client `ClientObfuscationSection`
3. Add `obfuscation_key` column to the SQLite `clients` table via schema migration
4. Generate a cryptographically random 256-bit key during `client add` when PSK is enabled
5. Include the obfuscation key in exported client TOML configs
6. Add `ServerContext` field for obfuscation key distribution

## Non-Goals

- ChaCha20 obfuscation logic (Step 1.2)
- Socket-level integration (Steps 1.3–1.4)
- Doctor diagnostic checks for PSK (Step 1.5)
- DNS-over-HTTPS (Feature 2)

## Requirements

**FR-DPI007-01**: `ObfuscationSection` SHALL include `psk_obfuscation: Option<bool>` and `obfuscation_key: Option<String>` fields.

**FR-DPI007-02**: `ClientObfuscationSection` SHALL include `psk_obfuscation: Option<bool>` and `obfuscation_key: Option<String>` fields.

**FR-DPI007-03**: SQLite schema migration (version 3) SHALL add a nullable `obfuscation_key` BLOB column to the `clients` table.

**FR-DPI007-04**: `ClientRecord` SHALL include an `obfuscation_key: Option<Vec<u8>>` field (32 bytes when present).

**FR-DPI007-05**: `ClientRegistry::add()` SHALL accept an optional obfuscation key parameter and persist it.

**FR-DPI007-06**: `handle_client_add` SHALL generate a 32-byte random key when server config has `psk_obfuscation = true`, and pass it to `registry.add()`.

**FR-DPI007-07**: `ServerContext` SHALL carry an optional `obfuscation_key` for inclusion in exported configs.

**FR-DPI007-08**: `generate_client_config()` SHALL emit `[obfuscation]` section with `psk_obfuscation = true` and `obfuscation_key = "<base64>"` when the server context provides a key.

**FR-DPI007-09**: All obfuscation key values SHALL be base64-encoded (standard alphabet) for TOML representation.

**NFR-DPI007-01**: Key generation SHALL use `rand::thread_rng()` (cryptographically secure).

**NFR-DPI007-02**: Schema migration SHALL be backward-compatible (existing databases upgraded transparently).

## Acceptance Criteria

- [x] AC-1: Server TOML with `psk_obfuscation = true` and `obfuscation_key` parses correctly
- [x] AC-2: Server TOML without PSK fields parses (backward compatible)
- [x] AC-3: Client TOML with `psk_obfuscation = true` and `obfuscation_key` parses correctly
- [x] AC-4: Client TOML without PSK fields parses (backward compatible)
- [x] AC-5: Registry stores and retrieves obfuscation key
- [x] AC-6: Registry add without obfuscation key stores NULL
- [x] AC-7: Client add with PSK enabled generates 32-byte key
- [x] AC-8: Client add without PSK enabled generates no key
- [x] AC-9: Exported TOML includes obfuscation section when key is present
- [x] AC-10: Exported TOML omits obfuscation section when no key
- [x] AC-11: QR code round-trip preserves obfuscation fields
- [x] AC-12: Schema migration v2→v3 adds column without data loss
- [x] AC-13: `make test` passes (637 tests: 584 lib + 23 integration + 30 bench)
- [x] AC-14: `make lint` clean

## Test Matrix

| ID | Type | Description |
|----|------|-------------|
| T-1 | Unit | Parse server TOML with PSK fields |
| T-2 | Unit | Parse server TOML without PSK fields (backward compat) |
| T-3 | Unit | Parse client TOML with PSK fields |
| T-4 | Unit | Parse client TOML without PSK fields (backward compat) |
| T-5 | Unit | Registry add with obfuscation key stores and retrieves |
| T-6 | Unit | Registry add without obfuscation key stores NULL |
| T-7 | Unit | CLI add with PSK enabled generates key |
| T-8 | Unit | CLI add without PSK enabled skips key |
| T-9 | Unit | Config export includes obfuscation section with key |
| T-10 | Unit | Config export omits obfuscation when no key |
| T-11 | Integration | QR round-trip with obfuscation fields |
| T-12 | Unit | Obfuscation key base64 encoding/decoding roundtrip |

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Schema migration breaks existing databases | High | Nullable column with no default; existing rows get NULL |
| Base64 key encoding inconsistency | Medium | Use `STANDARD` base64 consistently (same as public keys) |

## Rollback

- Remove added fields from config structs
- Remove schema migration (version stays at 2)
- Revert CLI and distribution changes

## Implementation

### Files Modified
- `src/config.rs` — added `psk_obfuscation: Option<bool>` and `obfuscation_key: Option<String>` to `ObfuscationSection` and `ClientObfuscationSection` (+6 tests)
- `src/registry.rs` — schema v2→v3 migration adding `obfuscation_key BLOB` column; `obfuscation_key: Option<Vec<u8>>` in `ClientRecord`; updated `add()` to accept 4th param; updated all 6 SELECT queries and `row_to_record()` (+5 tests)
- `src/cli.rs` — `handle_client_add` accepts `&ServerConfig`, generates 32-byte random key when `psk_obfuscation = true`; `build_server_context` reads `psk_obfuscation` from config (+3 tests)
- `src/distribution.rs` — `ServerContext` gains `psk_obfuscation: bool`; `generate_client_config()` emits `[obfuscation]` TOML section when `record.obfuscation_key` is present (+3 tests)
- `src/main.rs` — wired `config.obfuscation.psk_obfuscation` into `ServerContext` constructor
- `src/server.rs` — updated test helper `register_client` call site (4th arg)
- `src/diagnostics.rs` — updated 2 test `registry.add()` call sites (4th arg)
- `src/web/mod.rs` — added `psk_obfuscation: false` to test `ServerContext`
- `src/web/handlers.rs` — updated `registry.add()` and `ServerContext` in tests (4th arg + new field)
- `src/web/auth.rs` — added `psk_obfuscation: false` to test `ServerContext`
- `docs/configuration.md` — documented `psk_obfuscation` in server and client `[obfuscation]` tables
- `docs/obfuscation.md` — added PSK UDP Obfuscation section (key management, configuration, integration point)

### New Tests Added (17 total)
- `src/config.rs`: 6 tests (T-1 through T-4 + 2 default tests)
- `src/registry.rs`: 5 tests (T-5, T-6, T-12 + persistence/list/authenticate)
- `src/cli.rs`: 3 tests (T-7, T-8 + key uniqueness)
- `src/distribution.rs`: 3 tests (T-9, T-10, T-11)

## Traceability

- **Spec**: `specs/dpi-hardening-2/SPEC.MD` Section 2.3 (Configuration)
- **Roadmap**: `specs/dpi-hardening-2/ROADMAP.md` Step 1.1
