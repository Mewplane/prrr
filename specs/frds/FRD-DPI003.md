# FRD-DPI003: Proper TLS Certificate Verification (Client)

**Feature:** Feature 3 — Proper TLS Certificate Verification (Client)
**Status:** Done
**Created:** 2026-02-22
**Roadmap:** [specs/dpi-fixes/ROADMAP.md](../dpi-fixes/ROADMAP.md)
**Spec:** [specs/dpi-fixes/SPEC.md](../dpi-fixes/SPEC.md) — Fix 2 (DV-2)

## Overview

Replace the hardcoded `SkipServerVerification` with a configurable verifier. In production mode, the client verifies the server certificate against the Mozilla CA root store (`webpki-roots`). An explicit `--insecure` flag / `insecure_skip_verify` config option allows falling back to the current skip-verification behavior for dev/test.

## Motivation

The client currently accepts any server certificate (including self-signed, expired, or MITM-injected). This is detection vector DV-2: a DPI system can MITM the connection, present its own certificate, and the client will happily accept it. Proper certificate verification prevents this — a MITM cert won't chain to a trusted CA root.

## Goals

1. Add `build_cert_verifier(insecure: bool)` to `src/transport/tls.rs`
2. Add `insecure: bool` parameter to all client config builders
3. Add `--insecure` CLI flag to `ClientArgs`
4. Add `insecure_skip_verify` to `ClientTransportSection`
5. Thread the flag through `main.rs` -> `run_client` -> `build_masque_client_config`
6. Log a warning when insecure mode is active

## Non-Goals

- Server-side certificate loading (Feature 4)
- SNI validation or doctor checks (Feature 5)
- Changing ALPN or transport protocol behavior

## Requirements

**FR-DPI003-01**: `build_cert_verifier(false)` SHALL return a `WebPkiServerVerifier` using `webpki_roots::TLS_SERVER_ROOTS`.

**FR-DPI003-02**: `build_cert_verifier(true)` SHALL return `SkipServerVerification`.

**FR-DPI003-03**: `build_masque_client_config` SHALL accept `insecure: bool` and use `build_cert_verifier(insecure)`.

**FR-DPI003-04**: `build_insecure_client_config` SHALL be renamed to `build_client_config` and accept `insecure: bool`.

**FR-DPI003-05**: `build_mimicked_client_config` SHALL accept `insecure: bool` and use `build_cert_verifier(insecure)`.

**FR-DPI003-06**: `ClientArgs` SHALL have `--insecure` flag (default: false).

**FR-DPI003-07**: `ClientTransportSection` SHALL have `insecure_skip_verify: Option<bool>`.

**FR-DPI003-08**: `run_client` SHALL accept `insecure: bool` and pass it to `build_masque_client_config`.

**FR-DPI003-09**: When `insecure` is true, a warning SHALL be logged at startup.

**FR-DPI003-10**: All existing tests SHALL pass by explicitly setting `insecure: true`.

## Acceptance Criteria

- [x] `webpki-roots` added to `Cargo.toml`
- [x] `build_cert_verifier(insecure: bool)` implemented in `src/transport/tls.rs`
- [x] All three client config builders accept `insecure: bool`
- [x] `--insecure` flag in `ClientArgs`
- [x] `insecure_skip_verify` in `ClientTransportSection`
- [x] `run_client` accepts `insecure: bool`
- [x] Warning logged when insecure mode active
- [x] All existing tests pass with `insecure: true`
- [x] New tests for `build_cert_verifier` both modes
- [x] `make test` passes (538 passed)
- [x] `make lint` clean

## Implementation

### Files Created
(none)

### Files Modified
- `Cargo.toml` — add `webpki-roots`
- `src/transport/tls.rs` — add `build_cert_verifier(insecure: bool)`
- `src/transport/masque.rs` — add `insecure: bool` param to `build_masque_client_config`
- `src/transport/quic.rs` — rename `build_insecure_client_config` to `build_client_config`, add `insecure: bool`
- `src/obfuscation/tls_mimicry.rs` — add `insecure: bool` param to `build_mimicked_client_config`
- `src/config.rs` — add `--insecure` to `ClientArgs`, `insecure_skip_verify` to `ClientTransportSection`
- `src/client.rs` — add `insecure: bool` param to `run_client`, pass to builder
- `src/main.rs` — thread insecure flag from CLI/config to `run_client`
