# DPI Evasion Hardening Specification

**Status:** Draft
**Created:** 2026-02-22
**Priority:** Critical — actively causes blackholing in production

## Problem Statement

The prrr VPN server at `prrr.tech` (164.92.235.224) is intermittently detected and blackholed by Deep Packet Inspection (DPI) systems. Despite having a valid Let's Encrypt certificate and a real domain name, multiple code-level issues make the QUIC/TLS connection fingerprint distinguishable from legitimate HTTP/3 traffic.

### Production Environment

- **Domain:** prrr.tech (A record → 164.92.235.224)
- **Server:** DigitalOcean droplet `prrr-vpn` in fra1
- **Firewall:** UDP 443 open from 0.0.0.0/0
- **TLS cert:** Let's Encrypt (valid until 2026-05-22), covers `prrr.tech` and `admin.prrr.tech`
- **Server config:** `/etc/prrr/server.toml` with `server_name = "prrr.tech"`, `cert_path = "/etc/letsencrypt/live/prrr.tech/fullchain.pem"`, `key_path = "/etc/letsencrypt/live/prrr.tech/privkey.pem"`

## Detection Vectors

### DV-1: Server generates self-signed certificate (CRITICAL)

**Location:** `src/server.rs:77`

```rust
let (cert, key) = generate_self_signed_cert(vec![server_name.to_string()])?;
```

`run_multi_server()` always calls `generate_self_signed_cert()` and ignores any configured TLS certificate paths. The server.toml at `prrr.tech` has `cert_path` and `key_path` fields pointing to a valid Let's Encrypt certificate, but the Rust code has no fields in `TransportSection` to read them.

**DPI signal:** Self-signed certificates on port 443 are a strong indicator of non-standard traffic. Legitimate HTTPS/HTTP3 servers use CA-signed certificates. DPI systems maintain allowlists of trusted CAs and flag connections using unknown/self-signed issuers.

**Impact:** Every connection to the server presents a self-signed cert that no browser or standard client would accept. This is the single most likely cause of DPI detection.

### DV-2: Client skips all certificate verification (HIGH)

**Locations (3 duplicate implementations):**
- `src/transport/masque.rs:479` — `struct SkipServerVerification` (used by `build_masque_client_config`)
- `src/transport/quic.rs:86` — `struct SkipServerVerification` (used by `build_insecure_client_config`)
- `src/obfuscation/tls_mimicry.rs:304` — `struct SkipServerVerification` (used by `build_mimicked_client_config`)

All three blindly return `ServerCertVerified::assertion()` without checking anything. The client will accept any certificate from any server, including MITM proxies.

**DPI signal:** While DPI cannot directly observe that the client skips verification (it's a client-side behavior), this means:
1. Active DPI probes that MITM the connection succeed — the client happily talks to the probe, revealing the inner protocol.
2. If the server presents a self-signed cert (DV-1), the client doesn't reject it, perpetuating the use of non-standard certs.

**Security impact:** A DPI middlebox performing active interception can impersonate the server, terminate the QUIC connection, and inspect the inner MASQUE/handshake protocol. The Noise IK handshake layer provides authentication, but by then the DPI has already seen the non-standard inner protocol patterns.

### DV-3: Default SNI is `"www.google.com"` (HIGH)

**Location:** `src/config.rs:31`

```rust
pub const DEFAULT_SERVER_NAME: &str = "www.google.com";
```

If the client configuration does not explicitly set `[server].server_name = "prrr.tech"`, the TLS ClientHello carries SNI `www.google.com` while connecting to IP `164.92.235.224` (a DigitalOcean IP, not a Google IP).

**DPI signal:** SNI/IP mismatch is a well-known DPI heuristic. When the SNI hostname resolves to a completely different IP range than the connection target, DPI flags it as domain fronting or VPN traffic. This is one of the first checks performed by GFW (Great Firewall), Roskomnadzor, and commercial DPI appliances.

**Note:** If the user's client config already sets `server_name = "prrr.tech"`, this is not an active vector. But the dangerous default makes misconfiguration likely.

### DV-4: Limited TLS cipher suite set (MEDIUM)

**Location:** `src/obfuscation/tls_mimicry.rs`

All TLS profiles offer exactly 3 cipher suites:
- `TLS13_AES_256_GCM_SHA384`
- `TLS13_CHACHA20_POLY1305_SHA256`
- `TLS13_AES_128_GCM_SHA256`

Real browsers advertise 15+ cipher suites (including TLS 1.2 fallbacks like `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`). The extension ordering is also randomized differently than browsers.

**DPI signal:** JA3/JA4 fingerprinting can distinguish rustls-based clients from real browsers. The cipher suite count alone (3 vs 15+) is a strong differentiator. This is a known limitation of rustls — it only exposes TLS 1.3 cipher suites for QUIC.

**Mitigation difficulty:** This is a fundamental rustls limitation. Adding TLS 1.2 suites to a QUIC-only connection is not possible. However, real HTTP/3 clients (Chrome, Firefox) also use only TLS 1.3 suites for QUIC, so the difference is mainly in suite count (3 vs 5 typically for real QUIC clients). This is lower priority.

### DV-5: No TLS cert/key config fields in transport (DESIGN GAP)

**Location:** `src/config.rs:317-324`

```rust
pub struct TransportSection {
    pub protocol: Option<String>,
    pub max_idle_timeout: Option<u64>,
    pub keep_alive: Option<u64>,
}
```

The `TransportSection` has no `tls_cert` or `tls_key` fields. The production server.toml at prrr.tech uses `cert_path` and `key_path` fields, but these are silently ignored by the TOML parser (unknown fields are ignored per the existing serde config). The `WebAdminSection` has `tls_cert`/`tls_key` but those are for the admin HTTP interface, not the VPN transport.

### DV-6: SkipServerVerification duplicated 3 times (CODE SMELL)

Three identical copies of the same struct exist across `masque.rs`, `quic.rs`, and `tls_mimicry.rs`. This violates DRY and makes it harder to replace with proper verification — the fix must touch all three locations and ensure none are missed.

---

## Fixes

### Fix 1: Server loads CA-signed TLS certificate from config

**Priority:** Critical
**Effort:** Medium
**Files:** `src/config.rs`, `src/server.rs`, `src/main.rs`

#### 1.1 Add TLS cert fields to TransportSection

Add `tls_cert` and `tls_key` optional fields to `TransportSection`:

```rust
pub struct TransportSection {
    pub protocol: Option<String>,
    pub max_idle_timeout: Option<u64>,
    pub keep_alive: Option<u64>,
    /// Path to TLS certificate chain file (PEM format).
    /// When set, the server uses this CA-signed certificate instead of
    /// generating a self-signed one. Typically points to a Let's Encrypt
    /// fullchain.pem or equivalent.
    pub tls_cert: Option<String>,
    /// Path to TLS private key file (PEM format).
    /// Required when tls_cert is set.
    pub tls_key: Option<String>,
}
```

#### 1.2 Add PEM loading utility

Add a function to load PEM certificate chains and private keys from files. This requires the `rustls-pemfile` crate (actively maintained, part of the rustls ecosystem).

```rust
/// Load a PEM certificate chain and private key from files.
///
/// The cert file should contain the full chain (leaf + intermediates).
/// The key file should contain a single PKCS#8 or SEC1 private key.
pub fn load_pem_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TransportError>
```

#### 1.3 Modify server startup to prefer configured cert

In `run_multi_server()` and `main.rs`, change the certificate resolution order:

1. If `transport.tls_cert` and `transport.tls_key` are set → load PEM files
2. Otherwise → fall back to `generate_self_signed_cert()` (for dev/test)

Also support the production server.toml field names `cert_path`/`key_path` as aliases for backward compatibility with the deployed config.

#### 1.4 Update build_masque_server_config to accept cert chain

Currently `build_masque_server_config` takes a single `CertificateDer`. Change it to accept `Vec<CertificateDer>` so it can include intermediate certificates (required for Let's Encrypt — the chain is leaf + R3 intermediate).

#### 1.5 Server config validation

Add validation in `prrr server doctor`:
- If `tls_cert` is set but file doesn't exist → error
- If `tls_cert` is set but `tls_key` is missing → error
- Parse the PEM and verify it contains at least one certificate
- Warn if the certificate expires within 30 days
- Warn if `server_name` doesn't match any SAN in the certificate

### Fix 2: Client verifies server TLS certificate properly

**Priority:** High
**Effort:** Medium
**Files:** `src/transport/masque.rs`, `src/transport/quic.rs`, `src/obfuscation/tls_mimicry.rs`, `src/client.rs`, `src/config.rs`, `Cargo.toml`

#### 2.1 Add webpki-roots dependency

Add `webpki-roots` crate to Cargo.toml. This provides the Mozilla CA root store compiled into the binary, ensuring Let's Encrypt certificates are trusted without relying on the operating system's certificate store (important for Android/iOS where the system store is harder to access).

Alternative: `rustls-native-certs` loads from the OS store. `webpki-roots` is preferred for a VPN client that must work on all platforms predictably.

#### 2.2 Create proper certificate verifier

Replace all three `SkipServerVerification` implementations with a single shared verifier that:

1. **Default mode (production):** Uses `webpki-roots` CA store to verify the server's certificate chain against trusted CAs. This validates that the server presents a cert signed by Let's Encrypt (or any other trusted CA).

2. **Insecure mode (dev/test):** Continues to skip verification, but only when explicitly opted in via config flag `insecure_skip_verify = true` or `--insecure` CLI flag.

```rust
/// Build a TLS certificate verifier.
///
/// In production mode, verifies the server certificate against the Mozilla
/// CA root store (webpki-roots). In insecure mode (dev/test only), accepts
/// any certificate.
pub fn build_cert_verifier(insecure: bool) -> Arc<dyn ServerCertVerifier> {
    if insecure {
        Arc::new(SkipServerVerification)
    } else {
        // webpki-roots verifier
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(WebPkiServerVerifier::builder(Arc::new(root_store)).build().unwrap())
    }
}
```

#### 2.3 Unify SkipServerVerification to a single module

Move the `SkipServerVerification` struct to `src/transport/tls.rs` (new module) and re-export from there. Delete the 3 duplicate copies. The `build_cert_verifier()` function lives here too.

#### 2.4 Update client config builders

Modify these functions to accept an `insecure: bool` parameter:
- `build_masque_client_config(keep_alive, max_idle_timeout, insecure)`
- `build_insecure_client_config()` → rename to `build_client_config(insecure)`
- `build_mimicked_client_config(profile, insecure)`

#### 2.5 Client config flag

Add `insecure_skip_verify` to `ClientTransportSection`:

```rust
pub struct ClientTransportSection {
    pub protocol: Option<String>,
    pub keep_alive: Option<u64>,
    /// Skip TLS certificate verification (dev/test only).
    /// Default: false. When false, the client verifies the server's
    /// certificate against the Mozilla CA root store.
    pub insecure_skip_verify: Option<bool>,
}
```

And a `--insecure` flag to `ClientArgs`.

#### 2.6 Update all tests

All existing tests use `generate_self_signed_cert()` for test servers. These tests must pass `insecure: true` when building client configs. No test behavior changes — just parameter threading.

### Fix 3: Change default SNI to empty / require explicit config

**Priority:** High
**Effort:** Small
**Files:** `src/config.rs`, `src/main.rs`

#### 3.1 Remove misleading default

Change `DEFAULT_SERVER_NAME` from `"www.google.com"` to a value that forces explicit configuration:

Option A: Make `server_name` required (no default) — error if not set.
Option B: Change default to the server's actual hostname derived from the endpoint address.

**Recommended: Option A.** A VPN client connecting to a specific server should always know the server's domain name. The `"www.google.com"` default was a domain-fronting placeholder that actively causes SNI/IP mismatch detection.

#### 3.2 Validate SNI matches cert

When the client has proper cert verification (Fix 2), rustls will automatically reject connections where the SNI doesn't match the server's certificate SAN. This provides a natural enforcement mechanism.

#### 3.3 Client doctor check

Add a diagnostic check in `prrr client doctor`:
- If `server_name` is `"www.google.com"` → warn: "Default SNI 'www.google.com' will cause DPI detection. Set [server].server_name to your server's actual domain."
- If `server_name` doesn't look like a valid domain → warn

### Fix 4: Consolidate SkipServerVerification (refactor)

**Priority:** Medium (code quality, reduces risk of Fix 2 being incomplete)
**Effort:** Small
**Files:** `src/transport/tls.rs` (new), `src/transport/mod.rs`, `src/transport/masque.rs`, `src/transport/quic.rs`, `src/obfuscation/tls_mimicry.rs`

#### 4.1 Create `src/transport/tls.rs`

Move `SkipServerVerification` here. Export `build_cert_verifier(insecure: bool)`.

#### 4.2 Delete duplicates

Remove `SkipServerVerification` from `masque.rs`, `quic.rs`, and `tls_mimicry.rs`. Import from `transport::tls` instead.

### Fix 5: Server config backward compatibility

**Priority:** Medium
**Effort:** Small
**Files:** `src/config.rs`

#### 5.1 Support production field names

The deployed server.toml at prrr.tech uses `cert_path` and `key_path` (not `tls_cert`/`tls_key`). Add serde aliases:

```rust
pub struct TransportSection {
    // ...
    #[serde(alias = "cert_path")]
    pub tls_cert: Option<String>,
    #[serde(alias = "key_path")]
    pub tls_key: Option<String>,
}
```

This ensures the production config works without changes while also supporting the more descriptive `tls_cert`/`tls_key` names.

---

## Implementation Order

The fixes have dependencies and should be implemented in this order:

```
Fix 4 (refactor SkipServerVerification) ──┐
                                           ├──→ Fix 2 (client cert verification)
Fix 5 (config backward compat)           ─┤
                                           ├──→ Fix 1 (server loads real cert)
                                           │
                                           └──→ Fix 3 (fix default SNI)
```

### Phase 1: Foundation (Fix 4 + Fix 5)
1. **Fix 4:** Consolidate `SkipServerVerification` into `src/transport/tls.rs`
2. **Fix 5:** Add `tls_cert`/`tls_key` fields with aliases to `TransportSection`

### Phase 2: Server-side (Fix 1)
3. **Fix 1.2:** Add PEM loading utility
4. **Fix 1.3:** Server prefers configured cert over self-signed
5. **Fix 1.4:** `build_masque_server_config` accepts cert chain
6. **Fix 1.5:** Server doctor validation

### Phase 3: Client-side (Fix 2 + Fix 3)
7. **Fix 2.1:** Add `webpki-roots` dependency
8. **Fix 2.2:** Create proper certificate verifier using `build_cert_verifier()`
9. **Fix 2.4:** Update client config builders
10. **Fix 2.5:** Add `insecure_skip_verify` config + `--insecure` CLI flag
11. **Fix 2.6:** Update all tests to pass `insecure: true`
12. **Fix 3.1:** Remove `"www.google.com"` default SNI
13. **Fix 3.3:** Client doctor diagnostic check

### Phase 4: Validation
14. Deploy updated server binary to prrr.tech
15. Verify Let's Encrypt cert is served (check via `openssl s_client` or similar)
16. Connect client with `server_name = "prrr.tech"` and verify cert validation passes
17. Confirm DPI no longer blackholes the connection

---

## Dependencies

### New crate dependencies

| Crate | Version | Purpose | Maintained |
|-------|---------|---------|------------|
| `rustls-pemfile` | 2.x | Parse PEM cert chains and keys | Yes (rustls ecosystem) |
| `webpki-roots` | 0.26.x | Mozilla CA root store for cert verification | Yes (rustls ecosystem) |

Both are part of the official rustls project and are actively maintained.

### No new crate dependencies needed for

- Fix 3 (SNI default change) — pure config change
- Fix 4 (refactor) — code reorganization only
- Fix 5 (serde aliases) — serde already supports `#[serde(alias)]`

---

## Security Considerations

### Cert pinning (future enhancement, not in scope)

For maximum security, the client could pin the server's certificate or public key in addition to CA verification. This would prevent even a compromised CA from issuing a fraudulent cert for `prrr.tech`. However, this conflicts with Let's Encrypt's 90-day cert rotation. Certificate pinning is deferred to a future iteration.

### Insecure mode safeguards

The `--insecure` / `insecure_skip_verify` flag must:
- Log a prominent warning at startup: `"WARNING: TLS certificate verification is disabled. This is insecure and should only be used for development/testing."`
- Not be the default for any code path
- Be clearly documented as dev/test only

### Backward compatibility

- Existing client configs without `insecure_skip_verify` will default to `false` (secure mode). If the server still uses a self-signed cert, the client will reject the connection. This is the correct behavior — it forces both sides to be updated.
- The `--insecure` flag provides an escape hatch during the migration period.
- Server configs with `cert_path`/`key_path` will work via serde aliases.
- Server configs without any TLS cert config will continue using self-signed certs (dev/test).

---

## Test Strategy

### Unit tests
- PEM loading: valid cert chain, missing file, corrupt PEM, key/cert mismatch
- Certificate verifier: trusted cert accepted, self-signed rejected, expired rejected, wrong hostname rejected
- Config parsing: `tls_cert`/`tls_key` fields, `cert_path`/`key_path` aliases, missing key when cert present
- SNI validation: reject empty, reject default "www.google.com" with warning

### Integration tests
- Server with self-signed cert + client with `insecure: true` → connection succeeds (backward compat)
- Server with self-signed cert + client with `insecure: false` → connection rejected
- Server with CA-signed cert + client with `insecure: false` → connection succeeds
- End-to-end: full handshake + tunnel pipeline with proper cert verification

### Manual validation
- Deploy to prrr.tech with Let's Encrypt cert
- Verify cert chain via `echo | openssl s_client -connect prrr.tech:443 -alpn h3`
- Test from a network known to have DPI
- Monitor for blackholing over 48-hour period

---

## Metrics for Success

1. **Primary:** prrr.tech connection is no longer intermittently blackholed by DPI
2. **Secondary:** `openssl s_client` shows valid Let's Encrypt certificate chain (not self-signed)
3. **Tertiary:** Client rejects connections to servers with invalid/self-signed certs by default
