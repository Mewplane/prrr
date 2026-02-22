# Obfuscation Module

The `prrr::obfuscation` module provides anti-censorship techniques to make
PRRR traffic indistinguishable from legitimate HTTPS.

## Modules

### `obfuscation::tls_mimicry` — TLS Fingerprint Mimicry (F-010)

Configures the rustls `CryptoProvider` with browser-like cipher suite and
key exchange group ordering to avoid the default rustls TLS fingerprint.
DPI systems use JA3/JA4 fingerprints to identify non-browser TLS clients;
this module reorders the controllable TLS parameters to reduce detectability.

#### Limitations

rustls v0.23 has the following constraints that prevent exact browser mimicry:

- **Extension ordering** is randomized internally — no public API to control it.
- **Only 3 TLS 1.3 cipher suites** are available for QUIC (browsers advertise 15+ including TLS 1.2 suites).
- **Cannot add TLS 1.2 cipher suites** to a QUIC ClientHello.
- **JA4** always identifies rustls by cipher count (3 vs 15 for browsers).

This module provides **approximate** mimicry by reordering cipher suites and
key exchange groups — the fields that are controllable via `CryptoProvider`.

#### TLS Profiles

Three profiles are available:

| Profile | Cipher Suite Order | Key Exchange Group Order |
|---------|-------------------|-------------------------|
| `Chrome` | AES_256_GCM, CHACHA20_POLY1305, AES_128_GCM | X25519, secp256r1, secp384r1 |
| `Firefox` | AES_128_GCM, CHACHA20_POLY1305, AES_256_GCM | X25519, secp256r1, secp384r1 |
| `Default` | AES_256_GCM, AES_128_GCM, CHACHA20_POLY1305 | X25519, secp256r1, secp384r1 |

All profiles use the same set of cipher suites and groups — only the
ordering differs. Each produces a different JA3 fingerprint hash.

#### Usage

```rust
use prrr::obfuscation::tls_mimicry::{
    TlsProfile,
    build_mimicked_client_config,
    build_mimicked_server_config,
    compute_ja3_hash,
    ja3_components,
};
use prrr::transport::quic::generate_self_signed_cert;

// Choose a profile
let profile = TlsProfile::Chrome;

// Build QUIC configs with the profile applied
let (cert, key) = generate_self_signed_cert(vec!["example.com".to_string()]).unwrap();
let server_config = build_mimicked_server_config(profile, cert, key).unwrap();
let client_config = build_mimicked_client_config(profile).unwrap();

// Verify the JA3 fingerprint
let hash = compute_ja3_hash(profile);
println!("JA3 hash: {hash}");

// Inspect raw JA3 components
let components = ja3_components(profile);
println!("Cipher suites: {:?}", components.cipher_suites);
println!("Key exchange groups: {:?}", components.groups);
println!("JA3 string: {}", components.to_ja3_string());
```

#### Profile Selection from Configuration

`TlsProfile` implements `Display` and `FromStr` for use in config files:

```rust
use prrr::obfuscation::tls_mimicry::TlsProfile;

// Parse from string (case-insensitive)
let profile: TlsProfile = "chrome".parse().unwrap();
assert_eq!(profile, TlsProfile::Chrome);

// Display as string
assert_eq!(profile.to_string(), "chrome");
```

#### JA3 Fingerprint Computation

JA3 is computed as `MD5(TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats)`:

- **TLSVersion**: `771` (TLS 1.2 wire version, used in ClientHello even for TLS 1.3)
- **CipherSuites**: IANA identifiers in profile order, dash-separated
- **Extensions**: Empty (rustls randomizes extension ordering)
- **EllipticCurves**: IANA group identifiers in profile order, dash-separated
- **ECPointFormats**: `0` (uncompressed, standard for TLS 1.3)

Since extensions are not controllable, the computed JA3 is **partial** —
it verifies that cipher suite and group ordering are applied correctly.

#### CryptoProvider Customization

Under the hood, each profile builds a `rustls::CryptoProvider` with
reordered `cipher_suites` and `kx_groups` vectors:

```rust
use prrr::obfuscation::tls_mimicry::{TlsProfile, build_crypto_provider};

let provider = build_crypto_provider(TlsProfile::Chrome);
// provider.cipher_suites: [AES_256_GCM, CHACHA20_POLY1305, AES_128_GCM]
// provider.kx_groups: [X25519, secp256r1, secp384r1]
```

The provider is then passed to `rustls::ClientConfig::builder_with_provider()`
or `rustls::ServerConfig::builder_with_provider()`.

**Types:**
- `TlsProfile` — Enum: `Chrome`, `Firefox`, `Default`.
- `Ja3Components` — Raw JA3 fingerprint components for inspection.
- `ParseTlsProfileError` — Error for unknown profile names.

**Functions:**
- `build_crypto_provider(profile) -> CryptoProvider` — Build rustls provider with profile ordering.
- `ja3_components(profile) -> Ja3Components` — Extract JA3 components for a profile.
- `compute_ja3_hash(profile) -> String` — Compute MD5-hex JA3 hash.
- `build_mimicked_client_config(profile) -> Result<ClientConfig>` — Quinn client config with profile.
- `build_mimicked_server_config(profile, cert, key) -> Result<ServerConfig>` — Quinn server config with profile.

**Ja3Components fields:**
- `tls_version: u16` — TLS version (771).
- `cipher_suites: Vec<u16>` — IANA cipher suite identifiers in profile order.
- `groups: Vec<u16>` — IANA named group identifiers in profile order.
- `ec_point_formats: Vec<u16>` — EC point format values.
- `to_ja3_string() -> String` — Build the raw JA3 string before MD5 hashing.

### `obfuscation::traffic_morph` — Traffic Morphing Engine (F-011)

Packet-level traffic shaping: random padding to normalize packet sizes,
timing jitter to break traffic patterns, and dummy traffic generation.
The morpher operates at the byte level — pad before encryption, unpad
after decryption.

#### Wire Format (Padded Frame)

```text
[2-byte payload length (BE)] [payload bytes] [random padding bytes]
```

- **Payload length header** (2 bytes): Big-endian, max payload 65535 bytes.
- **Payload**: Original bytes.
- **Padding**: Cryptographically random bytes filling to the target size.
- **Dummy packets**: Payload length = 0, entire frame is random padding.

#### Padding Strategies

| Strategy | Behavior |
|----------|----------|
| `PowerOfTwo` | Pad to next power of 2 (min 4 bytes) |
| `HttpSizes` | Pad to nearest HTTP size: 128, 256, 512, 1024, 1460 |
| `FixedMtu(n)` | Pad to fixed MTU; fall back for oversized payloads |
| `None` | Only the 2-byte length header, no padding |

#### Usage

```rust
use prrr::obfuscation::traffic_morph::{
    TrafficMorpher, PaddingStrategy,
    unpad, is_dummy_packet, generate_dummy, compute_jitter,
};

// Create a morpher with PowerOfTwo strategy
let morpher = TrafficMorpher::new(PaddingStrategy::PowerOfTwo);

// Pad a payload
let padded = morpher.pad(b"hello world").unwrap();
assert!(padded.len().is_power_of_two());

// Unpad (strategy-independent)
let recovered = TrafficMorpher::unpad(&padded).unwrap();
assert_eq!(recovered, b"hello world");

// Generate and detect dummy packets
let dummy = generate_dummy(PaddingStrategy::PowerOfTwo);
assert!(is_dummy_packet(&dummy));

// Timing jitter (uniform 0..50ms)
let jitter = compute_jitter(50);
// tokio::time::sleep(jitter).await;
```

#### Strategy Selection from Configuration

`PaddingStrategy` implements `Display` and `FromStr`:

```rust
use prrr::obfuscation::traffic_morph::PaddingStrategy;

let strategy: PaddingStrategy = "power-of-two".parse().unwrap();
let strategy: PaddingStrategy = "fixed-mtu:1500".parse().unwrap();
```

#### Integration with EncryptedChannel

```text
Application layer
     ↓ payload
TrafficMorpher::pad(payload)
     ↓ framed (with padding)
EncryptedChannel::send(framed)
     ↓ encrypted wire bytes
MASQUE / network
     ↓ encrypted wire bytes
EncryptedChannel::recv(wire)
     ↓ framed (with padding)
TrafficMorpher::unpad(framed)
     ↓ payload (or discard if dummy)
Application layer
```

**Types:**
- `TrafficMorpher` — Pads and unpads payloads according to a padding strategy.
- `PaddingStrategy` — Enum: `PowerOfTwo`, `HttpSizes`, `FixedMtu(u16)`, `None`.
- `MorphConfig` — Bundles padding strategy + max jitter for convenience.
- `MorphError` — Errors for frame parsing failures.
- `ParsePaddingStrategyError` — Error for unknown strategy names.

**Functions:**
- `TrafficMorpher::new(strategy) -> TrafficMorpher` — Create a morpher.
- `TrafficMorpher::pad(payload) -> Result<Vec<u8>>` — Pad payload into framed buffer.
- `TrafficMorpher::unpad(framed) -> Result<Vec<u8>>` — Unpad framed buffer (strategy-independent).
- `unpad(framed) -> Result<Vec<u8>>` — Free function variant of unpad.
- `is_dummy_packet(framed) -> bool` — Check if a frame is a dummy packet.
- `generate_dummy(strategy) -> Vec<u8>` — Generate a dummy packet with padding.
- `compute_jitter(max_ms) -> Duration` — Random jitter from uniform `[0, max_ms)`.
- `MorphConfig::default_config()` — PowerOfTwo padding, 50ms max jitter.

### `obfuscation::probe_resist` — Active Probing Resistance (F-013)

Gates MASQUE tunnel access behind HMAC-BLAKE2s cookie authentication.
Unauthenticated connections receive a static decoy HTTP response
indistinguishable from a default nginx web server. Prevents active
probers (GFW, TSPU) from identifying the server as a PRRR node.

#### Authentication Flow

1. Client generates an `AuthToken` with a random 16-byte nonce, Unix
   timestamp, and BLAKE2s-256 HMAC keyed with a pre-shared key (PSK).
2. Token is base64url-encoded and sent as `Authorization: Bearer <token>`
   in the CONNECT-UDP request.
3. Server validates: rate limit → timestamp freshness (±30s) →
   HMAC integrity (constant-time) → nonce uniqueness (replay protection).
4. Valid → proceed to MASQUE tunnel and hybrid handshake.
5. Invalid → return static decoy HTTP response (no distinguishable error).

#### Token Wire Format

```text
[nonce: 16 bytes] [timestamp: 8 bytes (u64 BE)] [mac: 32 bytes (BLAKE2s-256)]
```

Total: 56 bytes raw, 75 characters base64url (no padding).

MAC is computed as:

```text
BLAKE2s-256(key=PSK, data="prrr-probe-resist-token-v1" || nonce || timestamp)
```

#### Authenticated Request Format

```text
CONNECT-UDP /tunnel HTTP/3\r\n
Authorization: Bearer <base64url_token>\r\n
\r\n
```

#### Decoy Response

```text
HTTP/3 200 OK\r\n
Content-Type: text/html; charset=utf-8\r\n
Content-Length: 80\r\n
Server: nginx/1.24.0\r\n
\r\n
<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>
```

#### Rate Limiting

Per-IP token bucket:

| Parameter | Value |
|-----------|-------|
| Burst capacity | 5 tokens |
| Refill rate | 20 tokens/second |
| Stale timeout | 60 seconds |
| IPv6 keying | /64 prefix (first 8 bytes) |

#### Replay Protection

Nonces are tracked in a `NonceSet` with 60-second expiry window
(2× the 30-second timestamp tolerance). A replayed token with the
same nonce is rejected.

#### Usage

```rust
use prrr::obfuscation::probe_resist::{
    AuthToken, NonceSet, RateLimiter, ProbeResistConfig,
    validate_masque_request, build_authenticated_request,
    build_decoy_response,
};

// Pre-shared key (32 bytes, distributed out-of-band)
let psk = [0x42u8; 32];

// Client: build authenticated CONNECT-UDP request
let request = build_authenticated_request(&psk);

// Server: validate incoming request
let config = ProbeResistConfig { psk };
let mut nonce_set = NonceSet::new();
let mut rate_limiter = RateLimiter::new();
let client_ip = "10.0.0.1".parse().unwrap();
let server_time = 1_700_000_000u64;

let is_valid = validate_masque_request(
    request.as_bytes(),
    &config,
    client_ip,
    server_time,
    &mut nonce_set,
    &mut rate_limiter,
);

if !is_valid {
    // Send decoy response
    let decoy = build_decoy_response();
    // send decoy over the bidi stream, then close
}
```

**Types:**
- `AuthToken` — HMAC-BLAKE2s authentication token (nonce + timestamp + MAC).
- `NonceSet` — Replay protection via expiring nonce tracking.
- `RateLimiter` — Per-IP token bucket rate limiter.
- `ProbeResistConfig` — Configuration struct bundling the PSK.
- `ProbeResistError` — Error enum for validation failures.

**Functions:**
- `AuthToken::generate(psk, timestamp) -> AuthToken` — Generate a new token.
- `AuthToken::validate(psk, raw, server_time) -> Result<nonce>` — Validate raw token bytes.
- `AuthToken::to_bytes() -> [u8; 56]` — Serialize to raw bytes.
- `AuthToken::to_base64() -> String` — Encode as base64url string.
- `AuthToken::from_base64(encoded) -> Result<Vec<u8>>` — Decode base64url token.
- `NonceSet::new() -> NonceSet` — Create empty nonce set.
- `NonceSet::insert(nonce) -> bool` — Insert nonce, returns false if replay.
- `NonceSet::cleanup()` — Remove expired nonces.
- `RateLimiter::new() -> RateLimiter` — Create rate limiter with defaults.
- `RateLimiter::check(ip) -> bool` — Check/consume a rate limit token.
- `RateLimiter::cleanup()` — Remove stale IP entries.
- `validate_masque_request(request, config, ip, time, nonces, limiter) -> bool` — Full validation pipeline.
- `build_authenticated_request(psk) -> String` — Build authenticated CONNECT-UDP request.
- `build_decoy_response() -> Vec<u8>` — Build static decoy HTTP response.

### `obfuscation::psk_udp` — PSK UDP Obfuscation (DPI-007/DPI-008)

Per-client pre-shared key (PSK) based UDP packet obfuscation using ChaCha20
stream cipher. When enabled, each client receives a unique 256-bit key during
registration. The key is included in exported client configs and used to
encrypt/decrypt QUIC UDP datagrams at the outermost layer, making traffic
indistinguishable from random data to DPI systems.

#### Key Management

- **Key generation**: 256-bit (32-byte) cryptographically random key generated
  via `rand::RngCore` during `prrr server client add`.
- **Storage**: Keys are stored as `BLOB` in the SQLite client registry
  (`obfuscation_key` column).
- **Distribution**: Keys are base64-encoded in the `[obfuscation]` section of
  exported client TOML configs.
- **Per-client isolation**: Each client gets a unique key. Compromising one
  client's key does not affect others.

#### Configuration

Server-side: enable PSK obfuscation in `server.toml`:

```toml
[obfuscation]
enabled = true
psk_obfuscation = true
```

When `psk_obfuscation = true`, every new client registered via
`prrr server client add` automatically receives a PSK. The key appears in
the client's exported config:

```toml
[obfuscation]
psk_obfuscation = true
obfuscation_key = "base64-encoded-256-bit-key"
```

Clients registered before PSK was enabled have `obfuscation_key = NULL` and
connect without PSK obfuscation (backward compatible).

#### Wire Format

```text
[Nonce (8 bytes, random)] [Obfuscated QUIC Payload (N bytes)]
```

- **Nonce**: 8 bytes of cryptographically random data, zero-padded to 12 bytes
  for ChaCha20's standard nonce size.
- **Payload**: ChaCha20 stream cipher applied with the PSK as key. Ciphertext
  length equals plaintext length (no expansion).
- **Total overhead**: 8 bytes per packet.

#### Usage

```rust
use prrr::obfuscation::psk_udp::PskObfuscator;

let key = [0x42u8; 32];
let obfuscator = PskObfuscator::new(key);

// Obfuscate before sending over the wire
let plaintext = b"QUIC packet data";
let packet = obfuscator.obfuscate(plaintext);

// Deobfuscate after receiving from the wire
let recovered = obfuscator.deobfuscate(&packet).unwrap();
assert_eq!(recovered, plaintext);
```

**Types:**
- `PskObfuscator` — ChaCha20-based UDP packet obfuscator keyed by a 256-bit PSK.
- `PskError` — Error enum for obfuscation failures (`PacketTooShort`).

**Methods:**
- `PskObfuscator::new(key: [u8; 32]) -> PskObfuscator` — Create from 256-bit PSK.
- `PskObfuscator::obfuscate(plaintext) -> Vec<u8>` — Encrypt with random nonce, return `nonce || ciphertext`.
- `PskObfuscator::deobfuscate(packet) -> Result<Vec<u8>, PskError>` — Decrypt, return plaintext.

#### Integration Point

PSK obfuscation sits at the outermost layer of the protocol stack:

```text
Application data
     ↓
TrafficMorpher: pad payload
     ↓
EncryptedChannel: ChaCha20-Poly1305 + replay protection
     ↓
PSK UDP Obfuscation: ChaCha20 stream cipher (per-packet)
     ↓
QUIC DATAGRAMs / UDP
```

#### Security Notes

- ChaCha20 is used as a stream cipher without authentication tag. This is
  intentional — QUIC already provides authenticated encryption via TLS 1.3.
  The outer layer only needs to randomize the wire format.
- 8-byte nonces provide a 2^64 space. Birthday collision probability reaches
  50% at ~2^32 packets (~4 billion) per key, which is acceptable for VPN
  session lifetimes.
- A wrong PSK will "decrypt" to garbage, but QUIC will reject the malformed
  packet at the TLS layer. No distinguishable error is produced.

#### Socket Integration (Client)

When PSK obfuscation is enabled in the client config, `run_client()` wraps the
QUIC UDP socket with `ObfuscatedUdpSocket` — a transparent wrapper implementing
quinn's `AsyncUdpSocket` trait:

- **Send path**: `try_send()` obfuscates each datagram (prepending 8-byte nonce)
  before forwarding to the real socket.
- **Recv path**: `poll_recv()` deobfuscates each datagram in-place before
  returning to quinn. Malformed packets (too short) are silently dropped.
- **GSO/GRO disabled**: Each datagram is individually wrapped/unwrapped.
- **MTU adjustment**: Effective MTU budget is reduced by 8 bytes when active.

The wrapping is performed via `quinn::Endpoint::new_with_abstract_socket()`,
ensuring zero changes to quinn's internal QUIC engine logic.

#### Socket Integration (Server)

When PSK obfuscation is enabled in the server config (`psk_obfuscation = true`
in `[obfuscation]`), `run_multi_server()` wraps the server's QUIC endpoint
socket with the same `ObfuscatedUdpSocket` wrapper used by the client:

- **Symmetric operation**: The server deobfuscates incoming client packets and
  obfuscates outgoing packets, using the same ChaCha20 + random nonce scheme.
- **Single server-wide key**: All clients connected to this server share the
  same PSK. Per-client key differentiation is not supported at the socket layer.
- **Key resolution**: The obfuscation key is read from `[obfuscation].obfuscation_key`
  (base64-encoded, 32 bytes). The shared `resolve_obfuscation_key()` helper in
  `config.rs` validates the key format.
- **Error on misconfiguration**: If `psk_obfuscation = true` but no valid key
  is provided, the server exits with a clear error message at startup.
- **Backward compatibility**: When `psk_obfuscation = false` or absent, the
  server creates its endpoint with `quinn::Endpoint::server()` exactly as before.

The wrapping uses `quinn::Endpoint::new_with_abstract_socket()` with
`Some(server_config)` to bind the QUIC server to the obfuscated socket.

## Architecture

### TLS Fingerprint Mimicry Flow

```text
Config (TOML/CLI)
     ↓
TlsProfile enum (Chrome | Firefox | Default)
     ↓
build_crypto_provider(profile)
     ↓
CryptoProvider { cipher_suites: [...], kx_groups: [...] }
     ↓
rustls::ClientConfig::builder_with_provider(provider)
     ↓
quinn::ClientConfig (with ALPN=h3, datagrams enabled)
     ↓
QUIC connection with reordered cipher suites in ClientHello
```

### Full Protocol Stack with Obfuscation

```text
Application data (IP packets, messages)
     ↓
TrafficMorpher (F-011): pad payload + random padding
     ↓
EncryptedChannel (F-005): ChaCha20-Poly1305 + replay protection
     ↓
Probe Resistance (F-013): HMAC-BLAKE2s cookie gate
  └─ Valid token → MASQUE tunnel proceeds
  └─ Invalid token → static decoy HTTP response
     ↓
MASQUE framing (F-007): HTTP Datagram
     ↓
QUIC DATAGRAMs (F-006): quinn native datagram API
     ↓
TLS 1.3 with mimicked fingerprint (F-010)
  └─ Cipher suites reordered per TlsProfile
  └─ Key exchange groups reordered per TlsProfile
  └─ ALPN=h3 (appears as HTTP/3)
     ↓
PSK UDP Obfuscation (DPI-007): ChaCha20 stream cipher per-packet
  └─ Per-client 256-bit PSK, randomizes QUIC wire bytes
  └─ Optional — only active when psk_obfuscation = true
     ↓
UDP/IP: standard port 443 traffic
```

### Doctor Checks (DPI-011)

Both `prrr server doctor` and `prrr client doctor` validate PSK obfuscation
configuration consistency:

| Condition | Status | Action |
|-----------|--------|--------|
| PSK not configured (disabled, no key) | Pass | No action needed |
| PSK enabled with valid 32-byte key | Pass | Configuration correct |
| PSK enabled but key missing | Fail | Set `obfuscation_key` |
| PSK enabled but key is invalid base64 | Fail | Fix key encoding |
| PSK enabled but key is wrong length | Fail | Use exactly 32 bytes |
| Key present but PSK disabled | Warn | Enable PSK or remove unused key |

Server doctor check: `check_server_psk_config()` validates `[obfuscation]`.
Client doctor check: `check_client_psk_config()` validates `[obfuscation]`.

Both checks produce actionable recommendations when misconfiguration is detected.

## Security Notes

- TLS fingerprint mimicry is one layer of a defense-in-depth strategy.
- Exact browser mimicry is not achievable with stock rustls — this reduces
  detectability but does not guarantee invisibility to sophisticated DPI.
- JA3 hash computation uses MD5 for compatibility with the JA3 standard;
  MD5 is not used for any security-critical purpose.
- The `SkipServerVerification` in config builders is for dev/test only.
  Production deployments should use proper certificate verification.
- Active probing resistance uses constant-time MAC comparison (`subtle`
  crate) to prevent timing side-channel attacks.
- All authentication failures produce the same decoy response — no
  distinguishable error codes, no timing differences between failure modes.
- The PSK must be distributed out-of-band. PSK compromise allows an
  attacker to authenticate as a legitimate client.
- Rate limiting prevents handshake flooding but does not prevent a
  distributed probe from many IPs. IPv6 /64 prefix grouping mitigates
  address rotation within a subnet.
- The static decoy response may be fingerprinted by its content. Future
  iterations could support configurable decoy content or reverse-proxy
  to a real backend.
- Nonce replay protection has a 60-second window. Tokens older than
  30 seconds are rejected by timestamp validation.
- No `unsafe` code (`#![deny(unsafe_code)]`).
