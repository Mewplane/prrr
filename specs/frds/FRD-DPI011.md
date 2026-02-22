# FRD-DPI011: PSK Obfuscation Doctor Checks

**Status**: Complete
**Roadmap Item**: Step 1.5 — PSK Obfuscation Doctor Checks and Documentation
**Spec**: specs/dpi-hardening-2/SPEC.MD

## Overview

Add diagnostic checks for PSK obfuscation configuration to both `prrr server doctor` and `prrr client doctor`. Detect misconfigurations (enabled without key, key without enabled, invalid key format, wrong key length) and produce actionable warnings/errors.

## Functional Requirements

### FR-1: Server PSK Configuration Check

A `check_server_psk_config()` function validates the server's `[obfuscation]` section:

| Condition | Status | Message |
|-----------|--------|---------|
| `psk_obfuscation` absent or false, no key | Pass | PSK obfuscation not configured |
| `psk_obfuscation = true`, valid 32-byte base64 key | Pass | PSK obfuscation configured (key: 32 bytes) |
| `psk_obfuscation = true`, key missing | Fail | PSK obfuscation enabled but obfuscation_key is missing |
| `psk_obfuscation = true`, invalid base64 | Fail | PSK obfuscation enabled but obfuscation_key is not valid base64 |
| `psk_obfuscation = true`, wrong key length | Fail | PSK obfuscation key must be exactly 32 bytes |
| `psk_obfuscation` absent/false, key present | Warn | obfuscation_key is set but psk_obfuscation is not enabled (unused key) |

### FR-2: Client PSK Configuration Check

A `check_client_psk_config()` function validates the client's `[obfuscation]` section:

| Condition | Status | Message |
|-----------|--------|---------|
| `psk_obfuscation` absent or false, no key | Pass | PSK obfuscation not configured |
| `psk_obfuscation = true`, valid 32-byte base64 key | Pass | PSK obfuscation configured (key: 32 bytes) |
| `psk_obfuscation = true`, key missing | Fail | PSK obfuscation enabled but obfuscation_key is missing |
| `psk_obfuscation = true`, invalid base64 | Fail | PSK obfuscation enabled but obfuscation_key is not valid base64 |
| `psk_obfuscation = true`, wrong key length | Fail | PSK obfuscation key must be exactly 32 bytes |
| `psk_obfuscation` absent/false, key present | Warn | obfuscation_key is set but psk_obfuscation is not enabled (unused key) |

### FR-3: Doctor Integration

- `check_server_psk_config()` is wired into `run_server_doctor()` after the TLS cert check.
- `check_client_psk_config()` is wired into `run_client_doctor()` after the MTU check.
- Each produces a recommendation on Warn/Fail.

### FR-4: Existing Checks Unaffected

All existing doctor checks continue to function identically. The new PSK checks are additive — appended to the end of the check list.

## Non-Functional Requirements

- **NFR-1**: Zero new dependencies.
- **NFR-2**: Check functions are pure (no I/O) — they inspect config structs only.

## Acceptance Criteria

- [x] AC-1: Server doctor warns when `psk_obfuscation = true` but key missing
- [x] AC-2: Server doctor warns when `psk_obfuscation = true` but key is invalid base64
- [x] AC-3: Server doctor validates key length is exactly 32 bytes after decode
- [x] AC-4: Server doctor warns when key present but `psk_obfuscation = false` (unused key)
- [x] AC-5: Server doctor passes when PSK not configured at all
- [x] AC-6: Server doctor passes when PSK correctly configured
- [x] AC-7: Client doctor warns when `psk_obfuscation = true` but key missing
- [x] AC-8: Client doctor warns when `psk_obfuscation = true` but key is invalid base64
- [x] AC-9: Client doctor validates key length is exactly 32 bytes
- [x] AC-10: Client doctor warns when key present but `psk_obfuscation = false`
- [x] AC-11: Client doctor passes when PSK not configured
- [x] AC-12: Client doctor passes when PSK correctly configured
- [x] AC-13: Existing server doctor checks unaffected (check count incremented by 1)
- [x] AC-14: Existing client doctor checks unaffected (check count incremented by 1)
- [x] AC-15: Recommendations generated for PSK Fail/Warn results

## Test Matrix

| ID | Scenario | Input | Expected |
|----|----------|-------|----------|
| T-DPI011-1 | Server PSK disabled, no key | psk=false, key=None | Pass |
| T-DPI011-2 | Server PSK enabled, valid key | psk=true, key=valid_b64_32B | Pass |
| T-DPI011-3 | Server PSK enabled, key missing | psk=true, key=None | Fail |
| T-DPI011-4 | Server PSK enabled, invalid b64 | psk=true, key="!!!" | Fail |
| T-DPI011-5 | Server PSK enabled, wrong length | psk=true, key=b64_16B | Fail |
| T-DPI011-6 | Server PSK disabled, key present | psk=false, key=valid_b64 | Warn |
| T-DPI011-7 | Client PSK disabled, no key | psk=false, key=None | Pass |
| T-DPI011-8 | Client PSK enabled, valid key | psk=true, key=valid_b64_32B | Pass |
| T-DPI011-9 | Client PSK enabled, key missing | psk=true, key=None | Fail |
| T-DPI011-10 | Client PSK enabled, invalid b64 | psk=true, key="!!!" | Fail |
| T-DPI011-11 | Client PSK enabled, wrong length | psk=true, key=b64_16B | Fail |
| T-DPI011-12 | Client PSK disabled, key present | psk=false, key=valid_b64 | Warn |
| T-DPI011-13 | Server doctor report includes PSK check | default config | 8 checks total |
| T-DPI011-14 | Client doctor report includes PSK check | default config | 5 checks (no endpoint) |
| T-DPI011-15 | Server doctor PSK fail produces recommendation | psk=true, no key | recommendation present |

## Implementation

**Files modified:**
- `src/diagnostics.rs` — Added `check_server_psk_config()`, `check_client_psk_config()`, `check_psk_config_inner()` shared helper, constants `CHECK_SERVER_PSK_CONFIG`, `CHECK_CLIENT_PSK_CONFIG`, `PSK_EXPECTED_KEY_LEN`. Wired into `run_server_doctor()` and `run_client_doctor()`. Added 15 tests (T-DPI011-1 through T-DPI011-15). Updated existing doctor report tests for new check counts.
- `docs/obfuscation.md` — Added "Doctor Checks (DPI-011)" section documenting validation rules.
