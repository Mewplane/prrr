# Crypto Module

The `prrr::crypto` module provides foundational cryptographic primitives for the PRRR protocol.

## Modules

### `crypto::x25519` — Diffie-Hellman Key Exchange

X25519 elliptic-curve Diffie-Hellman for establishing shared secrets.

```rust
use prrr::crypto::x25519::KeyPair;

let alice = KeyPair::generate();
let bob = KeyPair::generate();

let alice_shared = alice.diffie_hellman(&bob.public_key_bytes());
let bob_shared = bob.diffie_hellman(&alice.public_key_bytes());

assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
```

**Types:**
- `KeyPair` — X25519 key pair (secret + public). Generates from OS CSPRNG.
- `DhOutput` — Shared secret result. Access via `.as_bytes()` or `.to_bytes()`.

**Constants:**
- `KEY_LEN = 32` — byte length of X25519 keys

### `crypto::aead` — Authenticated Encryption

ChaCha20-Poly1305 AEAD for encrypting/decrypting data with associated data.

```rust
use prrr::crypto::aead;

let key = [0u8; aead::KEY_LEN]; // use a real key
let nonce = [0u8; aead::NONCE_LEN]; // NEVER reuse with same key

let ciphertext = aead::encrypt(&key, &nonce, b"plaintext", b"aad");
let plaintext = aead::decrypt(&key, &nonce, &ciphertext, b"aad").unwrap();
```

**Functions:**
- `encrypt(key, nonce, plaintext, aad) → Vec<u8>` — encrypt with authentication
- `decrypt(key, nonce, ciphertext, aad) → Result<Vec<u8>, CryptoError>` — decrypt and verify

**Constants:**
- `KEY_LEN = 32` — key size in bytes
- `NONCE_LEN = 12` — nonce size in bytes
- `TAG_LEN = 16` — authentication tag size in bytes

**Warning:** Nonce reuse with the same key is catastrophic. Callers must ensure monotonic nonces.

### `crypto::kdf` — Key Derivation & Hashing

HKDF-SHA256 for deriving keys and BLAKE2s (via BLAKE3) for hashing.

```rust
use prrr::crypto::kdf;

// One-shot key derivation
let derived = kdf::derive(b"salt", b"input-key", b"context-info", 64).unwrap();

// Step-by-step
let prk = kdf::extract(b"salt", b"input-key");
let okm = kdf::expand(&prk, b"context-info", 32).unwrap();

// Hashing
let digest = kdf::blake2s(b"data to hash");
```

**Functions:**
- `extract(salt, ikm) → [u8; 32]` — HKDF extract phase
- `expand(prk, info, length) → Result<Vec<u8>, CryptoError>` — HKDF expand phase
- `derive(salt, ikm, info, length) → Result<Vec<u8>, CryptoError>` — one-shot extract+expand
- `blake2s(data) → [u8; 32]` — BLAKE2s-256 hash (via BLAKE3)

**Constants:**
- `PRK_LEN = 32` — PRK size
- `MAX_OUTPUT_LEN = 8160` — maximum HKDF expand output (255 * 32)
- `BLAKE2S_DIGEST_LEN = 32` — hash digest size

### `crypto::hybrid_kex` — Hybrid Post-Quantum Key Exchange

Combines X25519 classical DH with ML-KEM-768 (FIPS 203) post-quantum KEM
to produce a single shared secret resilient against both classical and
quantum adversaries.

```rust
use prrr::crypto::hybrid_kex::{self, KemKeyPair};

// Responder generates a long-term KEM key pair
let responder_kem = KemKeyPair::generate();
let responder_ek = responder_kem.encapsulation_key_bytes();

// Initiator starts the exchange
let (state, init_msg) = hybrid_kex::initiate(&responder_ek).unwrap();

// Responder processes and derives shared secret
let (resp_secret, resp_msg) = hybrid_kex::respond(&responder_kem, &init_msg).unwrap();

// Initiator finalizes and derives the same shared secret
let init_secret = hybrid_kex::finalize(state, &resp_msg).unwrap();

assert_eq!(init_secret, resp_secret);
```

**Types:**
- `KemKeyPair` — ML-KEM-768 key pair. Call `.encapsulation_key_bytes()` for the public key.
- `InitiatorMessage` — sent from initiator to responder (X25519 pubkey + KEM ciphertext)
- `InitiatorState` — held by initiator between `initiate()` and `finalize()`
- `ResponderMessage` — sent from responder back to initiator (X25519 pubkey)

**Functions:**
- `KemKeyPair::generate()` — generate ML-KEM-768 key pair from OS CSPRNG
- `KemKeyPair::from_dk_bytes(bytes)` — reconstruct from serialized decapsulation key (2400 bytes)
- `KemKeyPair::dk_bytes()` — serialize decapsulation key to bytes
- `KemKeyPair::encapsulation_key_bytes()` — get public encapsulation key bytes
- `kem_encapsulate(ek_bytes) → Result<(ciphertext, secret), CryptoError>` — low-level KEM encap
- `initiate(responder_ek) → Result<(state, msg), CryptoError>` — start hybrid KEX
- `respond(kem_kp, init_msg) → Result<(secret, msg), CryptoError>` — process and respond
- `finalize(state, resp_msg) → Result<secret, CryptoError>` — complete KEX on initiator side

**Constants:**
- `SHARED_SECRET_LEN = 32` — combined shared secret size
- `KEM_CIPHERTEXT_LEN = 1088` — ML-KEM-768 ciphertext size
- `KEM_ENCAPSULATION_KEY_LEN = 1184` — ML-KEM-768 public key size
- `KEM_DECAPSULATION_KEY_LEN = 2400` — ML-KEM-768 private key size (serialized)

**Key derivation formula:**
```text
HKDF-SHA256(salt=[], ikm=x25519_shared || kem_shared, info="prrr-hybrid-kex-v1", len=32)
```

**Implicit rejection:** ML-KEM decapsulation with a wrong ciphertext returns a
pseudorandom secret (not an error). The protocol layer above (F-004 Hybrid
Handshake) detects mismatches via MAC verification failure.

## Error Handling

All fallible operations return `Result<T, CryptoError>`:

```rust
use prrr::crypto::CryptoError;

match result {
    Err(CryptoError::AeadDecryptFailed) => { /* authentication failed */ }
    Err(CryptoError::HkdfInvalidLength) => { /* output length out of bounds */ }
    Err(CryptoError::KemDecapsulationFailed) => { /* KEM decapsulation failed */ }
    Ok(data) => { /* success */ }
}
```

## Security Notes

- All crypto delegates to audited RustCrypto crates
- No `unsafe` code (`#![deny(unsafe_code)]`)
- Secret key types implement `Zeroize` for memory cleanup
- ChaCha20-Poly1305 provides constant-time tag verification (via `subtle` crate)
