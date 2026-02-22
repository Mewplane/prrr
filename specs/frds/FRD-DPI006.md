# FRD-DPI006: Server Doctor TLS Validation

**Feature:** Feature 6 — Server Doctor TLS Validation
**Status:** Done
**Created:** 2026-02-22
**Roadmap:** [specs/dpi-fixes/ROADMAP.md](../dpi-fixes/ROADMAP.md)
**Spec:** [specs/dpi-fixes/SPEC.md](../dpi-fixes/SPEC.md) — Fix 1.5

## Overview

Add TLS certificate validation checks to `prrr server doctor`. When `tls_cert`/`tls_key` are configured in the server config, the doctor validates that files exist, parse correctly, contain valid certificates, are not expired (or expiring soon), and that the configured `server_name` appears in the certificate's Subject Alternative Names (SANs).

## Motivation

A misconfigured TLS certificate is the most common deployment mistake. The server doctor should catch these issues before they cause connection failures or DPI detection.

## Goals

1. Add `x509-parser` dependency for certificate inspection
2. Implement `check_tls_cert` function in `src/diagnostics.rs`
3. Wire `check_tls_cert` into `run_server_doctor`
4. Validate: file existence, PEM parsing, expiry, SAN matching

## Non-Goals

- Automatic certificate renewal (ACME/certbot)
- Certificate chain validation (trust path to root CA)
- OCSP/CRL revocation checking

## Requirements

**FR-DPI006-01**: When `tls_cert` is configured but the file is missing, the doctor SHALL report a failure.

**FR-DPI006-02**: When `tls_cert` is configured but `tls_key` is missing, the doctor SHALL report a failure.

**FR-DPI006-03**: When the PEM file is corrupt or contains no certificates, the doctor SHALL report a failure.

**FR-DPI006-04**: When the leaf certificate expires within 30 days, the doctor SHALL report a warning.

**FR-DPI006-05**: When the leaf certificate has already expired, the doctor SHALL report a failure.

**FR-DPI006-06**: When `server_name` is not found in the certificate's SANs, the doctor SHALL report a warning.

**FR-DPI006-07**: When no TLS cert is configured, the doctor SHALL report a warning (self-signed fallback).

**FR-DPI006-08**: When all checks pass, the doctor SHALL report success with cert details.

## Acceptance Criteria

- [x] `x509-parser` added to `Cargo.toml`
- [x] `check_tls_cert` implemented in `src/diagnostics.rs`
- [x] Wired into `run_server_doctor`
- [x] Test: no TLS cert configured -> warn
- [x] Test: missing cert file -> fail
- [x] Test: missing key file -> fail
- [x] Test: valid cert -> pass
- [x] Test: expired cert -> fail
- [x] Test: cert expiring within 30 days -> warn
- [x] Test: SAN mismatch -> warn
- [x] `make test` passes
- [x] `make lint` clean

## Implementation

### Files Modified
- `Cargo.toml` — added `x509-parser = "0.18.0"`
- `src/diagnostics.rs` — added `check_tls_cert()` with file existence, PEM parsing, X.509 expiry, and SAN matching checks; wired into `run_server_doctor` with recommendations
