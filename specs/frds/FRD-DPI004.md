# FRD-DPI004: Server Loads CA-Signed TLS Certificate

**Feature:** Feature 4 — Server Loads CA-Signed TLS Certificate
**Status:** Done
**Created:** 2026-02-22
**Roadmap:** [specs/dpi-fixes/ROADMAP.md](../dpi-fixes/ROADMAP.md)
**Spec:** [specs/dpi-fixes/SPEC.md](../dpi-fixes/SPEC.md) — Fix 1 (DV-1)

## Overview

The server currently generates a self-signed certificate on every startup via `generate_self_signed_cert()`. This change adds a `load_pem_cert_and_key()` function that loads a CA-signed PEM certificate chain and private key from disk. When `tls_cert`/`tls_key` are configured in `[transport]`, the server uses the loaded cert. When absent, it falls back to self-signed generation for dev/test.

## Motivation

Self-signed certificates are the primary DPI detection vector (DV-1). Any DPI system can trivially detect a self-signed cert by checking the certificate chain. A CA-signed Let's Encrypt certificate makes the TLS handshake indistinguishable from a regular HTTPS server.

## Goals

1. Add `rustls-pemfile` dependency for PEM parsing
2. Implement `load_pem_cert_and_key(cert_path, key_path)` in `src/transport/tls.rs`
3. Update `run_multi_server` to load PEM cert when configured, fall back to self-signed
4. Pass `TransportSection` through to the server so it can read cert paths

## Non-Goals

- Certificate renewal or ACME integration
- Server doctor checks for cert validity (Feature 6)
- Changing the client certificate verification logic (Feature 3, already done)

## Requirements

**FR-DPI004-01**: `load_pem_cert_and_key(cert_path, key_path)` SHALL load PEM cert chain and private key from disk.

**FR-DPI004-02**: The function SHALL return `(Vec<CertificateDer>, PrivateKeyDer)` — a full cert chain.

**FR-DPI004-03**: The function SHALL return `TransportError` for missing files, corrupt PEM, or missing key.

**FR-DPI004-04**: `run_multi_server` SHALL load PEM cert when `transport.tls_cert` and `transport.tls_key` are both set.

**FR-DPI004-05**: `run_multi_server` SHALL fall back to `generate_self_signed_cert()` when either field is absent.

**FR-DPI004-06**: `build_masque_server_config` SHALL accept `Vec<CertificateDer>` (cert chain) instead of single `CertificateDer`.

## Acceptance Criteria

- [x] `rustls-pemfile` added to `Cargo.toml`
- [x] `load_pem_cert_and_key` implemented in `src/transport/tls.rs`
- [x] `build_masque_server_config` accepts `Vec<CertificateDer>`
- [x] `run_multi_server` uses loaded PEM or falls back to self-signed
- [x] Unit tests: valid PEM, missing file, corrupt PEM, missing key
- [x] Integration test: server with self-signed fallback still works
- [x] `make test` passes
- [x] `make lint` clean

## Implementation

### Files Modified
- `Cargo.toml` — added `rustls-pemfile = "2.2.0"`
- `src/transport/tls.rs` — added `load_pem_cert_and_key()` with 5 unit tests
- `src/transport/masque.rs` — `build_masque_server_config` accepts `Vec<CertificateDer>`
- `src/obfuscation/tls_mimicry.rs` — `build_mimicked_server_config` accepts `Vec<CertificateDer>`
- `src/server.rs` — cert resolution logic in `run_multi_server`, updated all callers to pass `vec![cert]`
- `src/main.rs` — resolves `tls_cert`/`tls_key` from server config, passes to `run_multi_server`
