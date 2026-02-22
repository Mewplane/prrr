# FRD-DPI010: Integrate PSK Obfuscation into QUIC Socket Layer (Server)

**Feature:** Step 1.4 — Server PSK Socket Integration
**Status:** Complete
**Created:** 2026-02-22
**Roadmap:** [specs/dpi-hardening-2/ROADMAP.md](../dpi-hardening-2/ROADMAP.md)
**Spec:** [specs/dpi-hardening-2/SPEC.MD](../dpi-hardening-2/SPEC.MD) — Section 2.2

## Overview

Wire the `PskObfuscator` (from Step 1.2) and `ObfuscatedUdpSocket` (from Step 1.3) into the server's QUIC endpoint. When PSK obfuscation is enabled in the server config, the server wraps its UDP socket so that all incoming QUIC packets are deobfuscated and all outgoing packets are obfuscated — symmetric to the client integration.

## Motivation

Step 1.3 added PSK socket wrapping to the client. For the obfuscation pipeline to work end-to-end, the server must perform the reverse: deobfuscate incoming packets (stripping the nonce, decrypting with ChaCha20) and obfuscate outgoing packets (prepending a nonce, encrypting). Since the server uses a single endpoint for all clients, a single server-wide PSK key is used.

## Goals

1. `run_multi_server()` conditionally wraps the quinn endpoint socket with `ObfuscatedUdpSocket` when PSK obfuscation is enabled
2. Server reads `obfuscation_key` from `ServerConfig.obfuscation` section (base64 decode, 32-byte validation)
3. When `psk_obfuscation = true` but no key is configured, server exits with a clear error message
4. Pass the resolved key through `main.rs` into `run_multi_server()`
5. Backward compatibility: server without PSK works exactly as before

## Non-Goals

- Client-side socket integration (Step 1.3 — already done)
- Diagnostic checks for PSK config (Step 1.5)
- End-to-end tests with both client and server PSK (Step 3.1)
- Per-client PSK differentiation (all clients share the server PSK)

## Requirements

**FR-DPI010-01**: `run_multi_server()` SHALL accept an optional 32-byte obfuscation key parameter.

**FR-DPI010-02**: When the obfuscation key is `Some`, `run_multi_server()` SHALL wrap the QUIC endpoint socket with `ObfuscatedUdpSocket` using `quinn::Endpoint::new_with_abstract_socket()`.

**FR-DPI010-03**: When the obfuscation key is `None`, `run_multi_server()` SHALL create the endpoint with `quinn::Endpoint::server()` exactly as before (no regression).

**FR-DPI010-04**: The server SHALL log an info message when PSK obfuscation is enabled, including the nonce overhead.

**FR-DPI010-05**: `main.rs` SHALL resolve the obfuscation key from `ServerConfig.obfuscation` — decode base64, validate 32-byte length.

**FR-DPI010-06**: When `psk_obfuscation = true` but `obfuscation_key` is absent or invalid, the server SHALL exit with a clear error message.

**FR-DPI010-07**: When `psk_obfuscation = false` or absent, no obfuscation key resolution is attempted.

**NFR-DPI010-01**: The wrapper SHALL add minimal latency (ChaCha20 is sub-microsecond per packet).

**NFR-DPI010-02**: The server SHALL remain `Send + Sync` safe with the wrapped socket.

## Acceptance Criteria

- [x] AC-1: `run_multi_server` accepts optional obfuscation key parameter
- [x] AC-2: Server endpoint wrapped with `ObfuscatedUdpSocket` when key is present
- [x] AC-3: Server endpoint created normally when key is `None`
- [x] AC-4: `main.rs` resolves key from server config via `resolve_obfuscation_key()`
- [x] AC-5: Error on psk_obfuscation=true but missing/invalid key (7 tests)
- [x] AC-6: Existing server tests pass unchanged (backward compat)
- [x] AC-7: `make test` passes (670 tests)
- [x] AC-8: `make lint` clean

## Test Matrix

| ID | Type | Description |
|----|------|-------------|
| T-1 | Unit | Server starts without PSK — no regression |
| T-2 | Unit | Server with PSK key wraps endpoint (verify via log or behavior) |
| T-3 | Unit | obfuscation key resolution: valid base64, 32 bytes |
| T-4 | Unit | obfuscation key resolution: invalid base64 returns error |
| T-5 | Unit | obfuscation key resolution: wrong length returns error |
| T-6 | Unit | obfuscation key resolution: psk_obfuscation=false returns None |
| T-7 | Unit | obfuscation key resolution: psk_obfuscation=true but no key returns error |

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Server endpoint creation differs from client | Low | Same `ObfuscatedUdpSocket` + `new_with_abstract_socket` pattern |
| All clients must use same PSK | Low | By design — server-wide key, per-client keys are a future enhancement |
| Server bind to privileged port with custom socket | Low | Bind std socket first, then wrap |

## Rollback

- Remove obfuscation key parameter from `run_multi_server()`
- Revert `main.rs` key resolution
- Revert endpoint wrapping in `run_multi_server()`

## Implementation

### Files Modified
- `src/server.rs` — added `obfuscation_key: Option<[u8; 32]>` parameter to `run_multi_server()`, conditional endpoint wrapping with `ObfuscatedUdpSocket` via `new_with_abstract_socket()`
- `src/config.rs` — added `resolve_obfuscation_key()` shared helper with `PSK_KEY_LEN`, `ERR_MISSING_PSK_KEY`, `ERR_INVALID_PSK_BASE64`, `ERR_WRONG_PSK_KEY_LEN` constants, 7 tests
- `src/main.rs` — refactored both server and client PSK key resolution to use `resolve_obfuscation_key()`; added `server_obfuscation_key` parameter to `run_multi_server()` call
- `docs/obfuscation.md` — added "Socket Integration (Server)" section

## Traceability

- **Spec**: `specs/dpi-hardening-2/SPEC.MD` Section 2.2
- **Roadmap**: `specs/dpi-hardening-2/ROADMAP.md` Step 1.4
- **Depends on**: FRD-DPI007 (config), FRD-DPI008 (core obfuscator), FRD-DPI009 (socket wrapper + client integration)
