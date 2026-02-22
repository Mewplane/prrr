# FRD-DPI009: Integrate PSK Obfuscation into QUIC Socket Layer (Client)

**Feature:** Step 1.3 — Client PSK Socket Integration
**Status:** Complete
**Created:** 2026-02-22
**Roadmap:** [specs/dpi-hardening-2/ROADMAP.md](../dpi-hardening-2/ROADMAP.md)
**Spec:** [specs/dpi-hardening-2/SPEC.MD](../dpi-hardening-2/SPEC.MD) — Section 2.2

## Overview

Wire the `PskObfuscator` (from Step 1.2) into the client's QUIC UDP socket path. All outgoing QUIC packets are obfuscated before hitting the network, and all incoming packets are deobfuscated before reaching the quinn QUIC engine. This is achieved by implementing quinn's `AsyncUdpSocket` trait as a wrapper around the real socket.

## Motivation

The `PskObfuscator` core (Step 1.2) provides encrypt/decrypt primitives, but they are not yet wired into the actual network path. To make QUIC traffic invisible to DPI, every UDP datagram must pass through the obfuscation layer transparently — without modifying quinn's internal logic.

## Goals

1. Implement `ObfuscatedUdpSocket` wrapper implementing `quinn::AsyncUdpSocket`
2. On `try_send()`: obfuscate each datagram before forwarding to the real socket
3. On `poll_recv()`: deobfuscate each received datagram before returning to quinn
4. Add `obfuscation_key: Option<[u8; 32]>` parameter to `run_client()`
5. Conditionally wrap the endpoint socket when PSK is configured
6. Adjust effective MTU by nonce overhead (8 bytes) when obfuscation is active

## Non-Goals

- Server-side socket integration (Step 1.4)
- Doctor diagnostic checks (Step 1.5)
- End-to-end integration tests with real server (Step 3.1)

## Requirements

**FR-DPI009-01**: `ObfuscatedUdpSocket` SHALL implement `quinn::AsyncUdpSocket` by wrapping an inner `Arc<dyn AsyncUdpSocket>`.

**FR-DPI009-02**: `try_send()` SHALL obfuscate the transmit contents via `PskObfuscator::obfuscate()` before forwarding to the inner socket.

**FR-DPI009-03**: `poll_recv()` SHALL deobfuscate each received datagram via `PskObfuscator::deobfuscate()` in-place before returning to quinn.

**FR-DPI009-04**: `poll_recv()` SHALL silently drop datagrams that fail deobfuscation (too short) and continue receiving.

**FR-DPI009-05**: `local_addr()`, `max_transmit_segments()`, `max_receive_segments()`, `may_fragment()`, and `create_io_poller()` SHALL delegate to the inner socket.

**FR-DPI009-06**: `run_client()` SHALL accept an optional 32-byte obfuscation key and conditionally wrap the endpoint socket.

**FR-DPI009-07**: When no obfuscation key is provided, `run_client()` SHALL behave identically to before (no regression).

**FR-DPI009-08**: When obfuscation is active, `TUNNEL_OVERHEAD_BYTES` SHALL increase by 8 (nonce length) for MTU budget logging.

**NFR-DPI009-01**: The wrapper SHALL add minimal latency (ChaCha20 is sub-microsecond per packet).

**NFR-DPI009-02**: The wrapper SHALL be `Send + Sync + Debug` as required by `AsyncUdpSocket`.

## Acceptance Criteria

- [x] AC-1: `ObfuscatedUdpSocket` implements `quinn::AsyncUdpSocket`
- [x] AC-2: `try_send` obfuscates before forwarding
- [x] AC-3: `poll_recv` deobfuscates before returning
- [x] AC-4: Invalid packets silently dropped in `poll_recv`
- [x] AC-5: Delegation methods pass through to inner socket
- [x] AC-6: `run_client` accepts optional obfuscation key
- [x] AC-7: No regression when key is `None`
- [x] AC-8: `make test` passes (663 tests)
- [x] AC-9: `make lint` clean

## Test Matrix

| ID | Type | Description |
|----|------|-------------|
| T-1 | Unit | ObfuscatedUdpSocket delegates local_addr to inner |
| T-2 | Unit | ObfuscatedUdpSocket delegates max_transmit_segments to inner |
| T-3 | Unit | ObfuscatedUdpSocket delegates may_fragment to inner |
| T-4 | Unit | try_send obfuscates payload (output differs from input) |
| T-5 | Unit | try_send output length is input + 8 (nonce) |
| T-6 | Unit | Obfuscated send → deobfuscated recv roundtrip recovers original |
| T-7 | Unit | poll_recv silently drops too-short packets |
| T-8 | Unit | PSK nonce overhead constant is 8 |

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| quinn `AsyncUdpSocket` trait changes in future versions | Medium | Pin quinn version; trait is stable in 0.11.x |
| GRO/GSO segmentation with obfuscation | Medium | Disable segmentation when obfuscation active (`max_transmit_segments` returns 1) |
| Buffer size mismatch after obfuscation | Medium | Allocate oversized recv buffers to account for nonce stripping |

## Rollback

- Remove `ObfuscatedUdpSocket` from `src/obfuscation/psk_udp.rs`
- Revert `run_client()` signature change
- Revert `main.rs` caller changes

## Implementation

### Files Modified
- `src/obfuscation/psk_udp.rs` — added `ObfuscatedUdpSocket` implementing `AsyncUdpSocket`, `PSK_NONCE_OVERHEAD` constant, 10 socket tests with `MockUdpSocket` test double
- `src/obfuscation/mod.rs` — updated FRD comment to include FRD-DPI009
- `src/client.rs` — added `obfuscation_key: Option<[u8; 32]>` parameter, conditional socket wrapping via `new_with_abstract_socket()`, MTU budget adjustment
- `src/main.rs` — added obfuscation key resolution from client config (base64 decode, 32-byte validation), passed to `run_client()`
- `src/server.rs` — updated all 10 `run_client()` call sites in tests to pass `None` for obfuscation key
- `docs/obfuscation.md` — added "Socket Integration (Client)" section

## Traceability

- **Spec**: `specs/dpi-hardening-2/SPEC.MD` Section 2.2
- **Roadmap**: `specs/dpi-hardening-2/ROADMAP.md` Step 1.3
- **Depends on**: FRD-DPI007 (config), FRD-DPI008 (core obfuscator)
