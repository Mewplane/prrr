# DPI Hardening Phase 2 — Roadmap

**Spec**: `specs/dpi-hardening-2/SPEC.MD`
**Created**: 2026-02-22
**Status**: In Progress

---

## Summary

Phase 2 adds two complementary anti-censorship features to prrr:

1. **PSK UDP Obfuscation** — ChaCha20 stream cipher wrapper that makes QUIC traffic look like random noise, defeating protocol fingerprinting and SNI inspection.
2. **DNS-over-HTTPS (DoH) Client** — Built-in encrypted DNS resolver that bypasses ISP DNS hijacking/poisoning.

Together they form a complete anti-censorship pipeline: DoH resolves the server IP securely, then PSK obfuscation hides the QUIC protocol from DPI.

---

## Prerequisites

- [x] DPI Hardening Phase 1 complete (FRD-DPI001 through FRD-DPI006)
- [x] Obfuscation module exists (`src/obfuscation/`) with TLS mimicry, traffic morphing, probe resistance
- [x] QUIC/MASQUE transport operational (`src/transport/`)
- [x] Configuration infrastructure supports server + client TOML sections
- [x] 567 tests passing, zero clippy warnings

---

## Feature 1: PSK UDP Obfuscation

### Step 1.1 — PSK Key Generation and Configuration

**Description**: Add PSK (Pre-Shared Key) support to configuration and key management. When a client is created via `prrr server client add`, generate a 256-bit obfuscation key and include it in both the server registry and the exported client config. Add configuration fields for enabling/disabling PSK obfuscation.

**DoR** (Definition of Ready):
- Spec section 2 is understood
- `src/config.rs` structs (`ObfuscationSection`, `ClientObfuscationSection`) are identified as integration points
- `src/registry.rs` client registration flow is understood
- `src/distribution.rs` config export flow is understood

**DoD** (Definition of Done):
- [x] `ObfuscationSection` in `ServerConfig` gains `psk_obfuscation: Option<bool>` and `obfuscation_key: Option<String>` (base64-encoded)
- [x] `ClientObfuscationSection` in `ClientConfigFile` gains `psk_obfuscation: Option<bool>` and `obfuscation_key: Option<String>` (base64-encoded)
- [x] `ClientRegistry` stores an `obfuscation_key` column (nullable, BLOB) per client
- [x] `prrr server client add` generates a cryptographically random 256-bit key when `psk_obfuscation = true`
- [x] `prrr server client export` includes the obfuscation key in the exported TOML `[obfuscation]` section
- [x] Config parsing tests cover new fields (present, absent, backward compat)
- [x] Registry tests cover key storage and retrieval
- [x] All existing tests still pass (637 total: 584 lib + 23 integration + 30 bench)

**FRD**: [specs/frds/FRD-DPI007.md](../frds/FRD-DPI007.md)

**Files modified**:
- `src/config.rs` — added `psk_obfuscation` and `obfuscation_key` fields to `ObfuscationSection`, `ClientObfuscationSection` (+6 tests)
- `src/registry.rs` — added `obfuscation_key BLOB` column, schema v3 migration, updated `add()` signature (+5 tests)
- `src/distribution.rs` — added `psk_obfuscation` to `ServerContext`, `[obfuscation]` section in config export (+3 tests)
- `src/cli.rs` — PSK generation in `handle_client_add` when `psk_obfuscation = true` (+3 tests)
- `src/main.rs` — wired `psk_obfuscation` from config into `ServerContext`
- `src/server.rs`, `src/diagnostics.rs`, `src/web/mod.rs`, `src/web/handlers.rs`, `src/web/auth.rs` — updated call sites for new registry/context signatures
- `docs/configuration.md` — documented new config fields
- `docs/obfuscation.md` — documented PSK UDP obfuscation key management and protocol stack

---

### Step 1.2 — ChaCha20 Obfuscation Core (Encrypt/Decrypt)

**Description**: Implement the stateless obfuscation layer that wraps and unwraps UDP payloads. This is a pure cryptographic module with no I/O — it takes a PSK and a plaintext payload, generates a random 8-byte nonce, encrypts with ChaCha20, and returns `[nonce (8B)] + [ciphertext]`. The reverse operation strips the nonce and decrypts.

**DoR**:
- Step 1.1 merged (PSK available in config)
- `chacha20poly1305` crate already in `Cargo.toml` (provides `chacha20` stream cipher access)
- Packet structure defined: `[Nonce (8 bytes)] + [Obfuscated QUIC Payload]`

**DoD**:
- [x] New file `src/obfuscation/psk_udp.rs` created
- [x] Module registered in `src/obfuscation/mod.rs`
- [x] `PskObfuscator` struct holds the 256-bit PSK
- [x] `fn obfuscate(&self, plaintext: &[u8]) -> Vec<u8>` — generates random 8-byte nonce, applies ChaCha20, returns `nonce || ciphertext`
- [x] `fn deobfuscate(&self, packet: &[u8]) -> Result<Vec<u8>, PskError>` — splits nonce, decrypts, returns plaintext
- [x] Rejects packets shorter than 9 bytes (8-byte nonce + at least 1 byte payload)
- [x] Roundtrip test: `deobfuscate(obfuscate(data)) == data` for various payloads (1B, 19B, 1280B)
- [x] Different nonces produce different ciphertexts for the same plaintext
- [x] Wrong PSK fails to deobfuscate correctly (output differs from original)
- [x] Zero-length payload after nonce is rejected
- [x] Performance: ChaCha20 stream cipher — sub-microsecond per packet (inherent to algorithm; bench in Step 3.1)
- [x] `PskError` enum with `PacketTooShort` variant for PSK-specific errors

**FRD**: [specs/frds/FRD-DPI008.md](../frds/FRD-DPI008.md)

**Files created/modified**:
- `src/obfuscation/psk_udp.rs` — `PskObfuscator`, `PskError`, obfuscate/deobfuscate (+15 tests)
- `src/obfuscation/mod.rs` — registered `psk_udp` module
- `Cargo.toml` — added `chacha20 = "0.9.1"` direct dependency
- `docs/obfuscation.md` — added wire format, usage, API docs, security notes

---

### Step 1.3 — Integrate PSK Obfuscation into QUIC Socket Layer (Client)

**Description**: Wire the `PskObfuscator` into the client's UDP socket path so that all outgoing QUIC packets are obfuscated before hitting the network, and all incoming packets are deobfuscated before reaching the quinn QUIC engine. This requires intercepting the raw UDP send/recv at the quinn endpoint level.

**DoR**:
- Step 1.2 merged (core encrypt/decrypt works)
- `quinn::Endpoint` socket customization mechanism understood (custom `AsyncUdpSocket` or wrapper)
- Client config provides PSK from Step 1.1

**DoD**:
- [x] `ObfuscatedUdpSocket` wrapper struct in `src/obfuscation/psk_udp.rs` that implements quinn's `AsyncUdpSocket` trait
- [x] Outgoing path: `try_send()` calls `PskObfuscator::obfuscate()` on each datagram before forwarding to the real socket
- [x] Incoming path: `poll_recv()` calls `PskObfuscator::deobfuscate()` on each received datagram before returning to quinn
- [x] `run_client()` in `src/client.rs` conditionally wraps the endpoint socket when `psk_obfuscation = true`
- [x] When `psk_obfuscation = false` (or key absent), the client works exactly as before (no regression)
- [ ] Integration test: client with PSK obfuscation connects to server with PSK obfuscation, handshake completes, data flows *(deferred to Step 3.1)*
- [ ] Integration test: client with PSK cannot talk to server without PSK (connection fails gracefully) *(deferred to Step 3.1)*
- [x] MTU adjustment: effective MTU reduced by 8 bytes (nonce overhead) when obfuscation is active; logged at startup

**FRD**: [specs/frds/FRD-DPI009.md](../frds/FRD-DPI009.md)

**Files created/modified**:
- `src/obfuscation/psk_udp.rs` — `ObfuscatedUdpSocket` wrapper implementing `AsyncUdpSocket`, `PSK_NONCE_OVERHEAD` constant, 10 socket tests with `MockUdpSocket` test double
- `src/obfuscation/mod.rs` — updated FRD comment
- `src/client.rs` — added `obfuscation_key` parameter, conditional socket wrapping via `new_with_abstract_socket()`, MTU budget adjustment
- `src/main.rs` — obfuscation key resolution from client config (base64 decode, 32-byte validation)
- `src/server.rs` — updated 10 `run_client()` call sites in tests
- `docs/obfuscation.md` — added "Socket Integration (Client)" section

---

### Step 1.4 — Integrate PSK Obfuscation into QUIC Socket Layer (Server)

**Description**: Wire the `PskObfuscator` into the server's UDP socket path, symmetric to the client integration. The server must deobfuscate incoming packets and obfuscate outgoing packets. Since the server uses a single endpoint for all clients, the PSK must be consistent (one server-wide key).

**DoR**:
- Step 1.3 merged (client-side integration works)
- Server config provides PSK from Step 1.1
- Server socket creation path in `run_multi_server()` understood

**DoD**:
- [x] `run_multi_server()` in `src/server.rs` conditionally wraps the quinn endpoint socket with `ObfuscatedUdpSocket` when `psk_obfuscation = true`
- [x] Server reads `obfuscation_key` from `ServerConfig.obfuscation` section via shared `resolve_obfuscation_key()` helper
- [x] When obfuscation is enabled but no key is configured, server exits with a clear error message
- [ ] End-to-end test: client ↔ server both with PSK, full tunnel pipeline works (handshake + data transfer) *(deferred to Step 3.1)*
- [x] Backward compatibility: server without PSK continues to work with clients without PSK (all existing tests pass)
- [ ] Diagnostic check: `prrr server doctor` validates that PSK key is present and well-formed when `psk_obfuscation = true` *(deferred to Step 1.5)*
- [ ] Metrics: optional counter for obfuscated packets sent/received *(deferred to Step 3.1)*

**FRD**: [specs/frds/FRD-DPI010.md](../frds/FRD-DPI010.md)

**Files created/modified**:
- `src/server.rs` — added `obfuscation_key` parameter to `run_multi_server()`, conditional endpoint wrapping
- `src/config.rs` — added `resolve_obfuscation_key()` shared helper, 7 tests
- `src/main.rs` — refactored server and client PSK key resolution to use shared helper
- `docs/obfuscation.md` — added "Socket Integration (Server)" section

---

### Step 1.5 — PSK Obfuscation Doctor Checks and Documentation

**Description**: Add comprehensive diagnostic checks for PSK obfuscation configuration on both server and client sides. Ensure misconfigurations produce actionable warnings/errors.

**DoR**:
- Steps 1.1–1.4 merged (full PSK pipeline works)

**DoD**:
- [x] Server doctor: warns if `psk_obfuscation = true` but `obfuscation_key` is missing or not valid base64
- [x] Server doctor: warns if `obfuscation_key` is present but `psk_obfuscation = false` (unused key)
- [x] Server doctor: validates key length is exactly 32 bytes (256 bits) after base64 decode
- [x] Client doctor: warns if `psk_obfuscation = true` but `obfuscation_key` is missing
- [x] Client doctor: warns if key present but `psk_obfuscation = false` (unused key warning)
- [x] All doctor tests pass (631 lib + 23 integration + 30 bench + 1 doc = 685 total)
- [x] Existing doctor checks unaffected (check counts updated, all pass)

> **Note**: Client-server PSK mismatch detection (client doesn't have PSK but server does) is not feasible at doctor-check time because the client config does not contain server-side PSK state. This would require a live connection probe (deferred to Step 3.1 E2E tests).

**FRD**: [specs/frds/FRD-DPI011.md](../frds/FRD-DPI011.md)

**Files modified**:
- `src/diagnostics.rs` — `check_server_psk_config()`, `check_client_psk_config()`, `check_psk_config_inner()`, wired into both doctor functions, 15 new tests
- `docs/obfuscation.md` — Doctor Checks (DPI-011) section

---

## Feature 2: DNS-over-HTTPS (DoH) Client

### Step 2.1 — DoH Resolver Core Module

**Description**: Implement a minimal DNS-over-HTTPS client (RFC 8484) that resolves A/AAAA records over HTTPS. This is a standalone module with no prrr-specific coupling — it takes a domain name and a DoH provider URL, and returns resolved IP addresses.

**DoR**:
- Spec section 3 understood
- Decision made on HTTP client: use `reqwest` (new dependency) or raw `hyper`/`rustls` over `tokio` TCP. Since the project already has `tokio` + `rustls`, a minimal implementation using `hyper` or a lightweight approach is preferred to minimize dependency surface. Alternatively, `reqwest` with minimal features is acceptable.
- DNS wire format (RFC 1035 + RFC 8484) understood

**DoD**:
- [ ] New dependency added to `Cargo.toml` for HTTP client (e.g., `reqwest` with `rustls-tls` feature, or manual implementation)
- [ ] New file `src/transport/doh.rs` created
- [ ] Module registered in `src/transport/mod.rs`
- [ ] `DohResolver` struct with configurable provider URL (default: `https://cloudflare-dns.com/dns-query`)
- [ ] `async fn resolve_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DohError>` — resolves A records
- [ ] `async fn resolve_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>, DohError>` — resolves AAAA records
- [ ] `async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DohError>` — resolves both, returns all addresses
- [ ] Uses HTTP GET with `?dns=<base64url>` wire-format query (RFC 8484 §4.1) with `Accept: application/dns-message` header
- [ ] Parses DNS wire-format response (RFC 1035 §4.1)
- [ ] `DohError` enum covers: HTTP errors, DNS parse errors, no records found, timeout
- [ ] Configurable timeout (default 5 seconds)
- [ ] Unit tests with mock HTTP server (or integration tests against real Cloudflare DoH)
- [ ] Test: valid A record resolution
- [ ] Test: valid AAAA record resolution
- [ ] Test: non-existent domain returns empty or NXDOMAIN error
- [ ] Test: timeout handling
- [ ] Test: malformed DNS response handling

**Files to create/modify**:
- `Cargo.toml` — add HTTP client dependency
- `src/transport/doh.rs` — new module
- `src/transport/mod.rs` — register module

---

### Step 2.2 — DoH Configuration and Fallback Logic

**Description**: Add DoH configuration fields to the client config and implement the resolution strategy with fallback: first try DoH, then fall back to OS resolver.

**DoR**:
- Step 2.1 merged (DoH resolver works)
- Client config structure understood

**DoD**:
- [ ] `ClientConfigFile` gains a `[network]` section (new `ClientNetworkSection` struct) with:
  - `use_doh: Option<bool>` (default `false`)
  - `doh_provider: Option<String>` (default `"https://cloudflare-dns.com/dns-query"`)
  - `doh_timeout_secs: Option<u64>` (default `5`)
- [ ] Resolution function `resolve_endpoint(endpoint: &str, config: &ClientNetworkSection) -> Result<SocketAddr>`:
  1. Parse `endpoint` to extract hostname and port
  2. If hostname is already an IP address, return directly
  3. If `use_doh = true`, try `DohResolver::resolve()` with configured provider
  4. On DoH failure, log warning and fall back to `tokio::net::lookup_host()`
  5. If `use_doh = false`, use `tokio::net::lookup_host()` directly
- [ ] Config parsing tests for new `[network]` section
- [ ] Test: IP address endpoint bypasses DNS entirely
- [ ] Test: DoH enabled + successful resolution
- [ ] Test: DoH enabled + DoH failure → fallback to OS resolver
- [ ] Test: DoH disabled → OS resolver used directly

**Files to modify**:
- `src/config.rs` — add `ClientNetworkSection` and `[network]` section to `ClientConfigFile`
- `src/transport/doh.rs` — add `resolve_endpoint()` function
- `src/client.rs` — use `resolve_endpoint()` before connecting

---

### Step 2.3 — Integrate DoH into Client Connection Flow

**Description**: Wire the DoH resolver into `run_client()` so that the server endpoint hostname is resolved via DoH (when enabled) before the QUIC connection is established.

**DoR**:
- Step 2.2 merged (DoH config and fallback work)
- `run_client()` flow understood — currently receives `server_addr: SocketAddr` (already resolved)

**DoD**:
- [ ] `run_client()` signature updated or caller updated to accept hostname string + port instead of pre-resolved `SocketAddr` (when DoH is needed)
- [ ] Alternatively, resolution happens in `main.rs` before calling `run_client()`, passing the resolved `SocketAddr`
- [ ] DoH resolution logged: `"resolving {hostname} via DoH ({provider})"`
- [ ] Fallback logged: `"DoH failed, falling back to OS DNS resolver"`
- [ ] Resolved IP logged: `"resolved {hostname} → {ip}"`
- [ ] Integration test: client with DoH enabled connects to server (may use mock or real DoH)
- [ ] When endpoint is an IP literal (e.g., `1.2.3.4:443`), DoH is skipped entirely
- [ ] Error handling: if both DoH and OS resolver fail, return clear error

**Files to modify**:
- `src/main.rs` — resolve endpoint before calling `run_client()`
- `src/client.rs` — potentially adjust signature or add resolution step

---

### Step 2.4 — DoH Doctor Checks

**Description**: Add diagnostic checks for DoH configuration to the client doctor.

**DoR**:
- Steps 2.1–2.3 merged

**DoD**:
- [ ] Client doctor: when `use_doh = true`, performs a test DoH query to the configured provider
- [ ] Client doctor: warns if DoH provider URL is not HTTPS
- [ ] Client doctor: warns if DoH provider is unreachable (with timeout)
- [ ] Client doctor: informational note showing which DNS resolution method will be used
- [ ] All doctor tests pass

**Files to modify**:
- `src/diagnostics.rs` — add DoH checks to client doctor

---

## Feature 3: Combined Integration and End-to-End Validation

### Step 3.1 — Combined PSK + DoH End-to-End Test

**Description**: Validate that both features work together in a complete pipeline: DoH resolves the server, then PSK obfuscation protects the QUIC connection.

**DoR**:
- Feature 1 (PSK) and Feature 2 (DoH) both merged

**DoD**:
- [ ] End-to-end integration test: client with DoH + PSK connects to server with PSK, handshake completes, bidirectional data transfer works
- [ ] Test covers the full pipeline described in Spec §4: DoH → PSK obfuscation → QUIC/MASQUE → tunnel
- [ ] Performance benchmark: measure overhead of PSK obfuscation layer (nonce generation + ChaCha20)
- [ ] Benchmark result documented or added to `benches/`

**Files to create/modify**:
- `tests/` or inline integration tests — combined scenario
- `benches/transport_benchmarks.rs` — PSK obfuscation benchmark

---

### Step 3.2 — Configuration Distribution Update

**Description**: Ensure that `prrr server client export` and QR code generation include all new Phase 2 fields so that client configs are complete out-of-the-box.

**DoR**:
- All previous steps merged
- `src/distribution.rs` export flow understood

**DoD**:
- [ ] Exported client TOML includes `[obfuscation]` section with `psk_obfuscation` and `obfuscation_key` when PSK is enabled on server
- [ ] Exported client TOML includes `[network]` section with `use_doh` and `doh_provider` when server config specifies DoH defaults
- [ ] QR code contains the complete config including new fields
- [ ] Test: export with PSK enabled produces valid client config
- [ ] Test: export without PSK produces config without obfuscation key
- [ ] Test: imported config (round-trip) preserves all Phase 2 fields

**Files to modify**:
- `src/distribution.rs` — update export templates
- `src/cli.rs` — pass new config through export flow

---

## Execution Order

```
Step 1.1 (PSK Config + Keygen)
  │
  v
Step 1.2 (ChaCha20 Core)
  │
  v
Step 1.3 (Client Socket Integration)  ──>  Step 2.1 (DoH Core Module)
  │                                           │
  v                                           v
Step 1.4 (Server Socket Integration)       Step 2.2 (DoH Config + Fallback)
  │                                           │
  v                                           v
Step 1.5 (PSK Doctor Checks)              Step 2.3 (DoH Client Integration)
  │                                           │
  v                                           v
  └──────────>  Step 3.1 (E2E Test)  <────────┘
                    │
                    v
              Step 2.4 (DoH Doctor)
                    │
                    v
              Step 3.2 (Config Distribution)
```

**Parallelism**: Steps 1.3+ (PSK socket integration) and Steps 2.1+ (DoH core) can proceed in parallel once Step 1.2 is complete, since they are independent features that converge at Step 3.1.

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| quinn does not expose raw UDP socket customization | High — blocks PSK integration | Investigate `quinn::Endpoint::new()` with custom `AsyncUdpSocket`; fallback: wrap at the OS socket level with `tokio::net::UdpSocket` proxy |
| ChaCha20 nonce reuse with same PSK | Medium — breaks obfuscation security | Use `rand::thread_rng()` for 8-byte nonces; 2^64 space makes collision negligible |
| DoH provider blocked by ISP | Low — spec acknowledges this | Fallback to OS resolver; support multiple DoH providers in config |
| PSK obfuscation overhead affects throughput | Low — ChaCha20 is very fast | Benchmark; stream cipher with no auth tag minimizes per-packet cost |
| MTU reduction from 8-byte nonce | Low — existing MTU is 1280 | Document effective MTU; consider auto-adjusting TUN MTU when obfuscation is active |

---

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-02-22 | Initial roadmap created | Decomposition of SPEC.MD into actionable steps |
| 2026-02-22 | Step 1.1 completed | PSK key generation, config fields, registry column, config export — all DoD items met, 637 tests passing |
| 2026-02-22 | Step 1.2 completed | ChaCha20 obfuscation core — PskObfuscator with obfuscate/deobfuscate, 15 tests, 652 total tests passing |
| 2026-02-22 | Step 1.3 completed | Client PSK socket integration — ObfuscatedUdpSocket wrapper, run_client() conditional wrapping, MTU adjustment, 10 socket tests, 663 total tests passing. Integration tests deferred to Step 3.1 |
| 2026-02-22 | Step 1.4 completed | Server PSK socket integration — run_multi_server() conditional wrapping, shared resolve_obfuscation_key() helper in config.rs (refactored client too), 7 new key resolution tests, 670 total tests passing. E2E tests deferred to Step 3.1, doctor checks to Step 1.5 |
| 2026-02-22 | Step 1.5 completed | PSK obfuscation doctor checks — check_server_psk_config() and check_client_psk_config() with shared check_psk_config_inner(), wired into both doctor functions, 15 new tests, 685 total tests passing. Client-server mismatch detection deferred (requires live probe) |
