# FRD-DPI001: Consolidate SkipServerVerification

**Feature:** Feature 1 — Consolidate SkipServerVerification (Refactor)
**Status:** Done
**Created:** 2026-02-22
**Roadmap:** [specs/dpi-fixes/ROADMAP.md](../dpi-fixes/ROADMAP.md)
**Spec:** [specs/dpi-fixes/SPEC.md](../dpi-fixes/SPEC.md) — Fix 4 (DV-6)

## Overview

Extract the three duplicate `SkipServerVerification` implementations into a single shared module `src/transport/tls.rs`. This is a pure refactor with zero behavior change — it creates a single location for TLS certificate verification logic, which is a prerequisite for Feature 3 (proper cert verification with `webpki-roots`).

## Motivation

The `SkipServerVerification` struct (a `rustls::client::danger::ServerCertVerifier` that accepts any certificate) is copy-pasted in three locations:

1. `src/transport/masque.rs` (lines 476-507)
2. `src/transport/quic.rs` (lines 88-120)
3. `src/obfuscation/tls_mimicry.rs` (lines 306-340)

This violates DRY and creates a maintenance burden: when Feature 3 replaces `SkipServerVerification` with a proper verifier, all three locations must be updated. Consolidating first ensures the replacement is done once in one place.

## Goals

1. Create `src/transport/tls.rs` with a single `SkipServerVerification` implementation
2. Delete all three duplicate implementations
3. Update all call sites to import from `crate::transport::tls`
4. Maintain identical behavior — all existing tests pass unchanged

## Non-Goals

- Adding proper certificate verification (Feature 3)
- Changing TLS configuration or ALPN settings
- Modifying any public API signatures

## Requirements

**FR-DPI001-01**: `src/transport/tls.rs` SHALL contain a single `SkipServerVerification` struct that implements `rustls::client::danger::ServerCertVerifier`.

**FR-DPI001-02**: `src/transport/mod.rs` SHALL declare `pub mod tls;`.

**FR-DPI001-03**: `src/transport/masque.rs` SHALL import `SkipServerVerification` from `super::tls` and SHALL NOT contain a local definition.

**FR-DPI001-04**: `src/transport/quic.rs` SHALL import `SkipServerVerification` from `super::tls` and SHALL NOT contain a local definition.

**FR-DPI001-05**: `src/obfuscation/tls_mimicry.rs` SHALL import `SkipServerVerification` from `crate::transport::tls` and SHALL NOT contain a local definition.

**FR-DPI001-06**: All existing tests SHALL pass without modification.

## Acceptance Criteria

- [x] `src/transport/tls.rs` exists with `SkipServerVerification`
- [x] `src/transport/mod.rs` declares `pub(crate) mod tls;`
- [x] Zero copies of `SkipServerVerification` in `masque.rs`, `quic.rs`, `tls_mimicry.rs`
- [x] All three files import from the `tls` module
- [x] `make test` passes (529 passed)
- [x] `make lint` clean

## Implementation

### Files Created
- `src/transport/tls.rs`

### Files Modified
- `src/transport/mod.rs`
- `src/transport/masque.rs`
- `src/transport/quic.rs`
- `src/obfuscation/tls_mimicry.rs`
