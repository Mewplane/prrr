# FRD-DPI002: Transport TLS Config Fields

**Feature:** Feature 2 — Transport TLS Config Fields
**Status:** Done
**Created:** 2026-02-22
**Roadmap:** [specs/dpi-fixes/ROADMAP.md](../dpi-fixes/ROADMAP.md)
**Spec:** [specs/dpi-fixes/SPEC.md](../dpi-fixes/SPEC.md) — Fix 1.1

## Overview

Add `tls_cert` and `tls_key` optional fields to the `[transport]` section in `ServerConfig` so the server can be configured to load a CA-signed TLS certificate instead of generating a self-signed one. This is a config-only change — no loading logic yet (that is Feature 4).

## Motivation

The server currently generates a self-signed certificate on every startup, which is the primary DPI detection vector (DV-1). To fix this, the server needs a way to be configured with paths to a CA-signed certificate and private key. This feature adds those config fields as the foundation for Feature 4 (actual PEM loading).

## Goals

1. Add `tls_cert: Option<String>` to `TransportSection`
2. Add `tls_key: Option<String>` to `TransportSection`
3. Ensure TOML parsing works with and without these fields
4. Update the full TOML test to include the new fields

## Non-Goals

- Loading or parsing PEM files (Feature 4)
- Changing server startup behavior based on these fields (Feature 4)
- Adding TLS fields to client config (not needed — client doesn't serve TLS)

## Requirements

**FR-DPI002-01**: `TransportSection` SHALL have a `tls_cert` field of type `Option<String>`.

**FR-DPI002-02**: `TransportSection` SHALL have a `tls_key` field of type `Option<String>`.

**FR-DPI002-03**: TOML without `tls_cert`/`tls_key` SHALL parse to `None` for both fields (no breakage).

**FR-DPI002-04**: TOML with `tls_cert`/`tls_key` SHALL parse the values correctly.

**FR-DPI002-05**: The `server_config_full_toml` test SHALL include `tls_cert` and `tls_key`.

## Acceptance Criteria

- [x] `TransportSection` has `tls_cert: Option<String>`
- [x] `TransportSection` has `tls_key: Option<String>`
- [x] TOML without TLS fields parses to `None`
- [x] TOML with TLS fields parses correctly
- [x] `server_config_full_toml` test updated
- [x] `make test` passes (531 passed)
- [x] `make lint` clean

## Implementation

### Files Modified
- `src/config.rs`
