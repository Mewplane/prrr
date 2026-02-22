# FRD-DPI005: Fix Default SNI & Client Doctor Check

**Feature:** Feature 5 — Fix Default SNI & Client Doctor Check
**Status:** Done
**Created:** 2026-02-22
**Roadmap:** [specs/dpi-fixes/ROADMAP.md](../dpi-fixes/ROADMAP.md)
**Spec:** [specs/dpi-fixes/SPEC.md](../dpi-fixes/SPEC.md) — Fix 3 (DV-3)

## Overview

Remove the dangerous `DEFAULT_SERVER_NAME = "www.google.com"` default that causes SNI/IP mismatch detection. Make `server_name` required for client connections (no default). The server retains its default since the server's `--server-name` is used for self-signed cert generation and is less critical. Add a client doctor diagnostic check that warns about misconfigured SNI values.

## Motivation

The current default `"www.google.com"` was a domain-fronting placeholder. When a client connects without explicitly setting `server_name`, the TLS ClientHello carries SNI `www.google.com` while connecting to a non-Google IP. Any DPI system can trivially detect this SNI/IP mismatch and flag the connection.

## Goals

1. Remove `DEFAULT_SERVER_NAME` constant (or change its value)
2. Make client `--server-name` required (no default) — the client CLI must explicitly provide it or the config must have it
3. Server `--server-name` retains a default for backward compatibility (self-signed cert generation)
4. Add SNI diagnostic checks to `run_client_doctor`

## Non-Goals

- Automatic SNI derivation from endpoint address
- Domain fronting support
- Server-side SNI validation (Feature 6 covers cert SAN matching)

## Requirements

**FR-DPI005-01**: The `DEFAULT_SERVER_NAME` constant SHALL be removed from `src/config.rs`.

**FR-DPI005-02**: The client `--server-name` CLI flag SHALL NOT have a default value. It SHALL be `Option<String>`.

**FR-DPI005-03**: The client connection path in `main.rs` SHALL resolve `server_name` from CLI > config > error. If neither provides a value, the client SHALL exit with a clear error message.

**FR-DPI005-04**: The server `--server-name` CLI flag SHALL use a sensible default (e.g., `"localhost"`) for dev/test self-signed cert generation.

**FR-DPI005-05**: `run_client_doctor` SHALL check if `server_name` is `"www.google.com"` and warn about DPI detection risk.

**FR-DPI005-06**: `run_client_doctor` SHALL check if `server_name` looks like a valid domain (contains at least one dot and no whitespace) and warn if not.

## Acceptance Criteria

- [x] `DEFAULT_SERVER_NAME` removed from `src/config.rs`
- [x] Client `--server-name` is `Option<String>` with no default
- [x] Client exits with clear error if no `server_name` is provided
- [x] Server `--server-name` has a default value for dev/test
- [x] Client doctor warns on `"www.google.com"` SNI
- [x] Client doctor warns on invalid-looking domain
- [x] Client doctor passes on valid domain
- [x] All tests updated and passing
- [x] `make test` passes
- [x] `make lint` clean

## Implementation

### Files Modified
- `src/config.rs` — removed `DEFAULT_SERVER_NAME`, added `DEFAULT_SERVER_SERVER_NAME = "localhost"` and `ERR_MISSING_SERVER_NAME`, changed `ClientArgs.server_name` to `Option<String>`
- `src/main.rs` — client resolves `server_name` from CLI > config > error
- `src/diagnostics.rs` — added `check_sni_config()` with `looks_like_valid_domain()` heuristic, wired into `run_client_doctor` with recommendation
