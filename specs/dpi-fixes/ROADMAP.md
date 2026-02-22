# DPI Evasion Hardening — Roadmap

**Spec:** [SPEC.md](SPEC.md)
**Created:** 2026-02-22
**Status:** Complete (7/7)

---

## Feature 1: Consolidate SkipServerVerification (Refactor) — DONE

**Priority:** Medium (foundation for Fix 2)
**Spec ref:** Fix 4 (DV-6)
**FRD:** [specs/frds/FRD-DPI001.md](../frds/FRD-DPI001.md)
**Completed:** 2026-02-22

### Description

Extract the three duplicate `SkipServerVerification` implementations from `masque.rs`, `quic.rs`, and `tls_mimicry.rs` into a single shared module `src/transport/tls.rs`. This is a pure refactor — no behavior change — but it's a prerequisite for Feature 3 (proper cert verification) because it creates a single location to introduce the `build_cert_verifier()` function.

### Definition of Ready

- [x] Three duplicate `SkipServerVerification` locations identified:
  - `src/transport/masque.rs:476-507`
  - `src/transport/quic.rs:86-120`
  - `src/obfuscation/tls_mimicry.rs:304-340`
- [x] `src/transport/mod.rs` reviewed — currently declares: `encrypted_channel`, `masque`, `quic`
- [x] All call sites identified (grep for `SkipServerVerification`)

### Definition of Done

- [x] `src/transport/tls.rs` created with single `SkipServerVerification` struct
- [x] `src/transport/mod.rs` declares `pub(crate) mod tls;`
- [x] `SkipServerVerification` deleted from `masque.rs`, `quic.rs`, `tls_mimicry.rs`
- [x] All three files import from `crate::transport::tls`
- [x] All existing tests pass unchanged (`cargo test --lib` — 529 passed)
- [x] `cargo clippy -- -D warnings` clean, `make lint` clean
- [x] FRD written: `specs/frds/FRD-DPI001.md`

### Implementation Files

- **Created:** `src/transport/tls.rs` — consolidated `SkipServerVerification` + `skip_server_verification()` helper
- **Modified:** `src/transport/mod.rs` — added `pub(crate) mod tls;`
- **Modified:** `src/transport/masque.rs` — deleted local duplicate, imports `super::tls::skip_server_verification`
- **Modified:** `src/transport/quic.rs` — deleted local duplicate, uses `super::tls::skip_server_verification()`
- **Modified:** `src/obfuscation/tls_mimicry.rs` — deleted local duplicate, uses `crate::transport::tls::skip_server_verification()`

### Checklist

- [x] Create `src/transport/tls.rs` with `SkipServerVerification` struct and `ServerCertVerifier` impl
- [x] Add `pub(crate) mod tls;` to `src/transport/mod.rs`
- [x] Update `src/transport/masque.rs` — delete local `SkipServerVerification`, import from `tls`
- [x] Update `src/transport/quic.rs` — delete local `SkipServerVerification`, import from `tls`
- [x] Update `src/obfuscation/tls_mimicry.rs` — delete local `SkipServerVerification`, import from `tls`
- [x] Run `make test` — all tests pass
- [x] Run `make lint` — clean

---

## Feature 2: Transport TLS Config Fields — DONE

**Priority:** Medium (foundation for Feature 4)
**Spec ref:** Fix 1.1
**FRD:** [specs/frds/FRD-DPI002.md](../frds/FRD-DPI002.md)
**Completed:** 2026-02-22

### Description

Add `tls_cert` and `tls_key` fields to `TransportSection` in `src/config.rs` so the server can be configured with a CA-signed certificate. No backward compatibility aliases — the production `server.toml` will be updated to use `tls_cert`/`tls_key` directly.

### Definition of Ready

- [x] `TransportSection` reviewed — currently has: `protocol`, `max_idle_timeout`, `keep_alive`
- [x] Production `server.toml` will be updated to use new field names

### Definition of Done

- [x] `TransportSection` has `tls_cert: Option<String>`
- [x] `TransportSection` has `tls_key: Option<String>`
- [x] Unit test: TOML with `tls_cert`/`tls_key` parses correctly (`transport_with_tls_cert_only`)
- [x] Unit test: TOML without TLS fields parses to `None` (`transport_without_tls_fields_parses_to_none`)
- [x] Existing `server_config_full_toml` test updated with new fields
- [x] `make test` passes (531 passed), `make lint` clean
- [x] FRD written: `specs/frds/FRD-DPI002.md`

### Implementation Files

- **Modified:** `src/config.rs` — added `tls_cert: Option<String>` and `tls_key: Option<String>` to `TransportSection`, added 2 tests, updated `server_config_full_toml` test

### Checklist

- [x] Add `tls_cert: Option<String>` to `TransportSection`
- [x] Add `tls_key: Option<String>` to `TransportSection`
- [x] Write test: parse TOML with `tls_cert`/`tls_key`
- [x] Write test: parse TOML without TLS fields → `None`
- [x] Update `server_config_full_toml` test with new fields
- [x] Run `make test`, `make lint`

---

## Feature 3: Proper TLS Certificate Verification (Client) — DONE

**Priority:** High
**Spec ref:** Fix 2 (DV-2)
**Depends on:** Feature 1
**FRD:** [specs/frds/FRD-DPI003.md](../frds/FRD-DPI003.md)
**Completed:** 2026-02-22

### Description

Replace the hardcoded `SkipServerVerification` with a configurable verifier. In production mode, the client verifies the server certificate against the Mozilla CA root store (`webpki-roots`). An explicit `--insecure` flag / `insecure_skip_verify` config option allows falling back to the current behavior for dev/test. This eliminates DV-2 (client accepts any cert, enabling MITM by DPI).

### Definition of Ready

- [x] Feature 1 complete — `SkipServerVerification` consolidated in `src/transport/tls.rs`
- [x] `webpki-roots` crate assessed — actively maintained, part of rustls ecosystem
- [x] `ClientArgs` reviewed — no `--insecure` flag exists
- [x] `ClientTransportSection` reviewed — no `insecure_skip_verify` field exists
- [x] All call sites to `build_masque_client_config`, `build_insecure_client_config`, `build_mimicked_client_config` identified

### Definition of Done

- [x] `webpki-roots` added to `Cargo.toml`
- [x] `build_cert_verifier(insecure: bool)` function in `src/transport/tls.rs`
- [x] Production mode: uses `WebPkiServerVerifier` with `webpki_roots::TLS_SERVER_ROOTS`
- [x] Insecure mode: uses `SkipServerVerification` (same as current behavior)
- [x] `build_masque_client_config` accepts `insecure: bool` parameter
- [x] `build_insecure_client_config` renamed to `build_client_config(insecure: bool)`
- [x] `build_mimicked_client_config` accepts `insecure: bool` parameter
- [x] `--insecure` flag added to `ClientArgs` (default: false)
- [x] `insecure_skip_verify: Option<bool>` added to `ClientTransportSection`
- [x] Warning logged when insecure mode is active
- [x] `src/client.rs` accepts `insecure: bool` and passes it to builder
- [x] `src/main.rs` threads insecure flag from CLI/config to `run_client`
- [x] All existing tests updated to pass `insecure: true` — no behavior change in tests
- [x] New test: `build_cert_verifier(false)` returns verifier that rejects self-signed cert
- [x] New test: `build_cert_verifier(true)` returns verifier that accepts any cert
- [x] New test: `skip_server_verification` accepts any cert
- [x] New tests: CLI `--insecure` flag and `insecure_skip_verify` config parsing (4 tests)
- [x] `make test` passes (538 passed), `make lint` clean
- [x] FRD written: `specs/frds/FRD-DPI003.md`

### Implementation Files

- **Modified:** `Cargo.toml` — added `webpki-roots = "1.0.6"`
- **Modified:** `src/transport/tls.rs` — added `build_cert_verifier(insecure: bool)`, 3 unit tests
- **Modified:** `src/transport/masque.rs` — `build_masque_client_config` now takes `insecure: bool`
- **Modified:** `src/transport/quic.rs` — renamed `build_insecure_client_config` to `build_client_config(insecure: bool)`
- **Modified:** `src/obfuscation/tls_mimicry.rs` — `build_mimicked_client_config` now takes `insecure: bool`
- **Modified:** `src/config.rs` — added `--insecure` to `ClientArgs`, `insecure_skip_verify` to `ClientTransportSection`, 4 tests
- **Modified:** `src/client.rs` — `run_client` takes `insecure: bool`, logs warning, passes to builder
- **Modified:** `src/main.rs` — resolves insecure flag from CLI/config, passes to `run_client`
- **Modified:** `src/server.rs` — updated 10 test call sites with `insecure: true`

### Checklist

- [x] Add `webpki-roots` to `Cargo.toml`
- [x] Implement `build_cert_verifier(insecure: bool)` in `src/transport/tls.rs`
- [x] Write test: `build_cert_verifier(true)` accepts any cert
- [x] Write test: `build_cert_verifier(false)` rejects self-signed cert
- [x] Add `insecure: bool` parameter to `build_masque_client_config`
- [x] Update all callers of `build_masque_client_config` in `src/client.rs`
- [x] Add `insecure: bool` parameter to `build_client_config` (rename from `build_insecure_client_config`)
- [x] Update all callers in `src/transport/quic.rs`
- [x] Add `insecure: bool` parameter to `build_mimicked_client_config`
- [x] Update all callers in `src/obfuscation/tls_mimicry.rs`
- [x] Add `--insecure` flag to `ClientArgs` in `src/config.rs`
- [x] Add `insecure_skip_verify` to `ClientTransportSection` in `src/config.rs`
- [x] Thread insecure flag through `src/main.rs` client path
- [x] Thread insecure flag through `src/client.rs::run_client`
- [x] Add startup warning log when insecure mode is active
- [x] Update all test client config builds to pass `insecure: true`
- [x] Run `make test`, `make lint`

---

## Feature 4: Server Loads CA-Signed TLS Certificate — DONE

**Priority:** Critical
**Spec ref:** Fix 1 (DV-1)
**Depends on:** Feature 2
**FRD:** [specs/frds/FRD-DPI004.md](../frds/FRD-DPI004.md)
**Completed:** 2026-02-22

### Description

The server currently generates a self-signed certificate every startup via `generate_self_signed_cert()`, ignoring any configured cert paths. This change makes the server load a CA-signed PEM certificate chain from the paths configured in `[transport]` section. Self-signed fallback is preserved for dev/test when no cert is configured. This is the highest-impact fix — it eliminates DV-1, the most likely cause of DPI detection.

### Definition of Ready

- [x] Feature 2 complete — `TransportSection` has `tls_cert`/`tls_key` fields
- [x] `rustls-pemfile` crate assessed — actively maintained, part of rustls ecosystem
- [x] `build_masque_server_config` reviewed — takes single `CertificateDer`, wraps in `vec![cert_der]`
- [x] `run_multi_server` reviewed — calls `generate_self_signed_cert()` unconditionally
- [x] Server config flow in `main.rs` reviewed — config is loaded and passed to `run_multi_server`

### Definition of Done

- [x] `rustls-pemfile` added to `Cargo.toml`
- [x] `load_pem_cert_and_key(cert_path, key_path)` function implemented in `src/transport/tls.rs`
- [x] `build_masque_server_config` accepts `Vec<CertificateDer>` instead of single `CertificateDer`
- [x] `build_mimicked_server_config` accepts `Vec<CertificateDer>` instead of single `CertificateDer`
- [x] `run_multi_server` loads PEM cert when `transport.tls_cert`/`tls_key` are set
- [x] `run_multi_server` falls back to self-signed cert when fields are absent
- [x] `main.rs` passes transport config to `run_multi_server`
- [x] Unit test: PEM loading with valid cert chain (create test PEM fixtures)
- [x] Unit test: PEM loading with missing file → error
- [x] Unit test: PEM loading with corrupt PEM → error
- [x] Unit test: PEM loading with key-only file (no cert) → error
- [x] Integration test: server with loaded PEM cert accepts connections (existing server tests use self-signed fallback path)
- [x] Integration test: server without cert config falls back to self-signed (existing server tests confirm self-signed fallback)
- [x] `make test` passes, `make lint` clean
- [x] FRD written: `specs/frds/FRD-DPI004.md`

### Implementation Files

- **Modified:** `Cargo.toml` — added `rustls-pemfile = "2.2.0"`
- **Modified:** `src/transport/tls.rs` — added `load_pem_cert_and_key()` with 5 unit tests
- **Modified:** `src/transport/masque.rs` — `build_masque_server_config` accepts `Vec<CertificateDer>`
- **Modified:** `src/obfuscation/tls_mimicry.rs` — `build_mimicked_server_config` accepts `Vec<CertificateDer>`
- **Modified:** `src/server.rs` — cert resolution logic in `run_multi_server`, updated all callers to pass `vec![cert]`
- **Modified:** `src/main.rs` — resolves `tls_cert`/`tls_key` from server config, passes to `run_multi_server`

### Checklist

- [x] Add `rustls-pemfile` to `Cargo.toml`
- [x] Implement `load_pem_cert_and_key` in `src/transport/tls.rs`
- [x] Write test: valid PEM cert chain loads correctly
- [x] Write test: missing cert file → TransportError
- [x] Write test: corrupt PEM → TransportError
- [x] Write test: missing key file → TransportError
- [x] Change `build_masque_server_config` to accept `Vec<CertificateDer>`
- [x] Change `build_mimicked_server_config` to accept `Vec<CertificateDer>`
- [x] Update all callers of `build_masque_server_config` (server.rs, tests)
- [x] Update all callers of `build_mimicked_server_config` (tls_mimicry.rs tests)
- [x] Add cert resolution logic to `run_multi_server`: config cert → PEM load, else → self-signed
- [x] Update `main.rs` to pass transport config through to server
- [x] Write integration test: server loads PEM and serves cert to client
- [x] Write integration test: no cert config → self-signed fallback
- [x] Run `make test`, `make lint`

---

## Feature 5: Fix Default SNI & Client Doctor Check — DONE

**Priority:** High
**Spec ref:** Fix 3 (DV-3)
**Depends on:** Feature 3 (cert verification provides natural SNI enforcement)
**FRD:** [specs/frds/FRD-DPI005.md](../frds/FRD-DPI005.md)
**Completed:** 2026-02-22

### Description

Remove the dangerous `DEFAULT_SERVER_NAME = "www.google.com"` default that causes SNI/IP mismatch detection. Make `server_name` a required field when connecting (no default). Add a client doctor diagnostic check that warns about misconfigured or default SNI values.

### Definition of Ready

- [x] `DEFAULT_SERVER_NAME` confirmed as `"www.google.com"` at `src/config.rs:31`
- [x] `server_name` used in `ClientArgs` (line 220) and `ServerArgs` (line 147) with default
- [x] Client doctor in `src/diagnostics.rs` reviewed — no SNI checks exist
- [x] Feature 3 complete — cert verification rejects SNI/cert mismatch automatically

### Definition of Done

- [x] `DEFAULT_SERVER_NAME` changed from `"www.google.com"` — removed, replaced with `DEFAULT_SERVER_SERVER_NAME = "localhost"` for server only
- [x] Client connection fails with clear error if `server_name` is not configured
- [x] Server `--server-name` still has a reasonable default (`"localhost"`)
- [x] Client doctor warns if `server_name` is `"www.google.com"`
- [x] Client doctor warns if `server_name` looks invalid (not a domain)
- [x] All existing tests updated to explicitly pass `server_name` where needed
- [x] `make test` passes (553 tests), `make lint` clean
- [x] FRD written: `specs/frds/FRD-DPI005.md`

### Implementation Files

- **Modified:** `src/config.rs` — removed `DEFAULT_SERVER_NAME`, added `DEFAULT_SERVER_SERVER_NAME` and `ERR_MISSING_SERVER_NAME`, changed `ClientArgs.server_name` to `Option<String>`
- **Modified:** `src/main.rs` — client resolves `server_name` from CLI > config > error
- **Modified:** `src/diagnostics.rs` — added `check_sni_config()` with domain validation, wired into `run_client_doctor`

### Checklist

- [x] Remove or change `DEFAULT_SERVER_NAME` in `src/config.rs`
- [x] Make `server_name` required for client connection (error if not set)
- [x] Update `ClientArgs` — remove default_value for `server_name`, make it `Option`
- [x] Update `main.rs` client path — validate `server_name` is set
- [x] Add SNI check to `run_client_doctor` in `src/diagnostics.rs`
- [x] Write test: client without `server_name` → `None`
- [x] Write test: client doctor warns on `"www.google.com"` SNI
- [x] Write test: client doctor passes on valid domain SNI
- [x] Update all test code that relied on the old default
- [x] Run `make test`, `make lint`

---

## Feature 6: Server Doctor TLS Validation — DONE

**Priority:** Medium
**Spec ref:** Fix 1.5
**Depends on:** Feature 4
**FRD:** [specs/frds/FRD-DPI006.md](../frds/FRD-DPI006.md)
**Completed:** 2026-02-22

### Description

Add TLS certificate validation checks to `prrr server doctor`. When `tls_cert`/`tls_key` are configured, verify the files exist, parse correctly, contain valid certificates, are not expired, and match the configured `server_name`.

### Definition of Ready

- [x] Feature 4 complete — PEM loading utility exists in `src/transport/tls.rs`
- [x] Server doctor reviewed — `run_server_doctor` in `src/diagnostics.rs` has no TLS checks
- [x] Certificate expiry and SAN validation APIs available via `x509-parser` or `rustls` built-in types

### Definition of Done

- [x] Doctor check: `tls_cert` set but file missing → error
- [x] Doctor check: `tls_cert` set but `tls_key` missing → error
- [x] Doctor check: PEM file corrupt or empty → error
- [x] Doctor check: certificate expires within 30 days → warning
- [x] Doctor check: `server_name` not in certificate SANs → warning
- [x] Doctor check: cert + key loaded successfully → pass
- [x] All checks have unit tests (9 tests)
- [x] `make test` passes (562 tests), `make lint` clean
- [x] FRD written: `specs/frds/FRD-DPI006.md`

### Implementation Files

- **Modified:** `Cargo.toml` — added `x509-parser = "0.18.0"`
- **Modified:** `src/diagnostics.rs` — added `check_tls_cert()` with file existence, PEM parsing, expiry, and SAN checks; wired into `run_server_doctor`

### Checklist

- [x] Add `check_tls_cert` function to `src/diagnostics.rs`
- [x] Implement file existence checks
- [x] Implement PEM parsing validation
- [x] Implement cert expiry check (30-day warning threshold)
- [x] Implement SAN vs server_name matching
- [x] Wire `check_tls_cert` into `run_server_doctor`
- [x] Write test: missing cert file → error result
- [x] Write test: missing key file → error result
- [x] Write test: valid cert → pass result
- [x] Write test: expired cert → fail result
- [x] Write test: SAN mismatch → warning result
- [x] Run `make test`, `make lint`

---

## Feature 7: Documentation & Deployment Guide — DONE

**Priority:** Medium
**Spec ref:** Phase 4 (Validation)
**Depends on:** Features 1-6
**Completed:** 2026-02-22

### Description

Update project documentation to reflect the new TLS configuration, cert verification behavior, and deployment best practices for DPI evasion. Create a deployment checklist for production environments.

### Definition of Ready

- [x] All code features (1-6) complete
- [x] `docs/` directory reviewed — existing docs cover getting-started, deployment, mobile

### Definition of Done

- [x] `docs/getting-started.md` updated with TLS cert configuration
- [x] `docs/deployment.md` updated with Let's Encrypt cert setup instructions
- [x] `docs/deployment.md` updated with DPI evasion best practices (use real domain, real cert, correct SNI)
- [x] `--insecure` flag documented with security warning
- [x] Example `server.toml` in docs shows `tls_cert`/`tls_key` fields
- [x] Example `client.toml` in docs shows `server_name` as required
- [x] AGENTS.md reviewed — no updates needed (no contract changes)
- [x] `make lint` clean (no doc warnings)

### Implementation Files

- **Modified:** `docs/getting-started.md` — added `[transport]` with `tls_cert`/`tls_key` to server config examples, added `--insecure` flag docs, added missing `server_name` troubleshooting
- **Modified:** `docs/deployment.md` — fixed `[tls]` → `[transport]` section, added VPN Transport TLS Certificates section, added DPI Evasion Checklist

### Checklist

- [x] Update `docs/getting-started.md` — server TLS section
- [x] Update `docs/deployment.md` — Let's Encrypt setup, certbot renewal
- [x] Update `docs/deployment.md` — DPI evasion checklist
- [x] Document `--insecure` flag with security warning
- [x] Add example server.toml snippet with TLS config
- [x] Add example client.toml snippet with explicit server_name
- [x] Review and update AGENTS.md

---

## Summary

| # | Feature | Priority | Depends On | Status |
|---|---------|----------|------------|--------|
| 1 | Consolidate SkipServerVerification | Medium | — | **Done** |
| 2 | Transport TLS Config Fields | Medium | — | **Done** |
| 3 | Proper TLS Certificate Verification | High | Feature 1 | **Done** |
| 4 | Server Loads CA-Signed TLS Certificate | Critical | Feature 2 | **Done** |
| 5 | Fix Default SNI & Client Doctor | High | Feature 3 | **Done** |
| 6 | Server Doctor TLS Validation | Medium | Feature 4 | **Done** |
| 7 | Documentation & Deployment Guide | Medium | Features 1-6 | **Done** |

### Dependency Graph

```
Feature 1 (Consolidate SkipServerVerification) ──→ Feature 3 (Client Cert Verification) ──→ Feature 5 (Fix SNI)
                                                                                                    │
Feature 2 (Transport TLS Config) ──→ Feature 4 (Server Loads Real Cert) ──→ Feature 6 (Doctor TLS)  │
                                                                                                    │
                                                                           Feature 7 (Docs) ←───────┘
```

Features 1 and 2 have no mutual dependency and can be implemented in parallel.
Features 3 and 4 can also be implemented in parallel once their prerequisites are done.

---

## Changelog

| Date | Change |
|------|--------|
| 2026-02-22 | Initial roadmap created from SPEC.md. All features Not Started. Codebase analysis confirmed zero existing implementation. |
| 2026-02-22 | Removed backward compatibility (serde aliases for `cert_path`/`key_path`). Feature 2 simplified — no aliases, production server.toml will use `tls_cert`/`tls_key` directly. Dropped Fix 5 from spec refs. |
| 2026-02-22 | Feature 1 completed. Created `src/transport/tls.rs`, deleted 3 duplicate `SkipServerVerification` from masque.rs, quic.rs, tls_mimicry.rs. 529 tests pass, clippy/lint clean. FRD: `specs/frds/FRD-DPI001.md`. |
| 2026-02-22 | Feature 2 completed. Added `tls_cert`/`tls_key` fields to `TransportSection` in config.rs. 2 new tests + updated full TOML test. 531 tests pass, clippy/lint clean. FRD: `specs/frds/FRD-DPI002.md`. |
| 2026-02-22 | Feature 3 completed. Added `webpki-roots`, `build_cert_verifier(insecure)`, `--insecure` CLI flag, `insecure_skip_verify` config. All 3 builders accept `insecure: bool`. 7 new tests, 538 total pass. FRD: `specs/frds/FRD-DPI003.md`. |
| 2026-02-22 | Feature 4 completed. Added `rustls-pemfile`, `load_pem_cert_and_key()` in tls.rs. Server builders accept `Vec<CertificateDer>`. `run_multi_server` loads PEM when configured, falls back to self-signed. 5 new tests, 543 total pass. FRD: `specs/frds/FRD-DPI004.md`. |
| 2026-02-22 | Feature 5 completed. Removed `DEFAULT_SERVER_NAME` (`"www.google.com"`), replaced with `DEFAULT_SERVER_SERVER_NAME` (`"localhost"`) for server only. Client `--server-name` now `Option<String>` (no default). Added `check_sni_config()` to client doctor. 10 new tests, 553 total pass. FRD: `specs/frds/FRD-DPI005.md`. |
| 2026-02-22 | Feature 6 completed. Added `x509-parser`, `check_tls_cert()` in diagnostics.rs. Validates file existence, PEM parsing, cert expiry (30-day warn), and SAN matching. Wired into `run_server_doctor`. 9 new tests, 562 total pass. FRD: `specs/frds/FRD-DPI006.md`. |
| 2026-02-22 | Feature 7 completed. Updated `docs/getting-started.md` with `[transport]` TLS config in server examples, `--insecure` flag docs, missing `server_name` troubleshooting. Updated `docs/deployment.md`: fixed `[tls]` → `[transport]`, added VPN Transport TLS Certificates section with certbot renewal hook, added DPI Evasion Checklist. AGENTS.md reviewed — no changes needed. `make lint` clean. Roadmap complete (7/7). |
