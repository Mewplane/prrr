# Handshake Module

The `prrr::handshake` module provides Noise protocol handshake implementations for establishing authenticated, encrypted sessions.

## Modules

### `handshake::noise_ik` — Noise IK Handshake

Implements the Noise_IK handshake pattern (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) using the `snow` crate (v0.10.0). The IK pattern provides mutual authentication with initiator identity hiding.

```text
IK:
  <- s
  ...
  -> e, es, s, ss    (message 1: initiator -> responder)
  <- e, ee, se       (message 2: responder -> initiator)
```

**Properties:**
- Mutual authentication: both sides verify each other's static keys
- Initiator identity hiding: the initiator's static key is encrypted in message 1
- Forward secrecy: ephemeral keys ensure past sessions remain secure
- 1-RTT: complete handshake in 2 messages

#### Usage

```rust
use prrr::handshake::noise_ik::{KeyPair, Initiator, Responder};

// Both sides generate long-term static key pairs
let client_kp = KeyPair::generate().unwrap();
let server_kp = KeyPair::generate().unwrap();

// Client (initiator) knows server's public key
let mut client = Initiator::new(&client_kp, server_kp.public_key()).unwrap();
let mut server = Responder::new(&server_kp).unwrap();

// Message 1: client -> server (e, es, s, ss)
let msg1 = client.write_message(b"").unwrap();
let _payload1 = server.read_message(&msg1).unwrap();

// Server can now verify client's identity
let client_key = server.remote_static_key().unwrap();
assert_eq!(client_key, *client_kp.public_key());

// Message 2: server -> client (e, ee, se)
let msg2 = server.write_message(b"").unwrap();
let _payload2 = client.read_message(&msg2).unwrap();

// Both sides transition to transport mode
let mut client_transport = client.into_transport().unwrap();
let mut server_transport = server.into_transport().unwrap();

// Encrypted communication
let ct = client_transport.write_message(b"hello server").unwrap();
let pt = server_transport.read_message(&ct).unwrap();
assert_eq!(pt, b"hello server");
```

#### Handshake Payloads

Both handshake messages can carry encrypted payloads:

```rust
use prrr::handshake::noise_ik::{KeyPair, Initiator, Responder};

let client_kp = KeyPair::generate().unwrap();
let server_kp = KeyPair::generate().unwrap();

let mut client = Initiator::new(&client_kp, server_kp.public_key()).unwrap();
let mut server = Responder::new(&server_kp).unwrap();

// Payloads are encrypted as part of the handshake
let msg1 = client.write_message(b"client hello").unwrap();
let payload1 = server.read_message(&msg1).unwrap();
assert_eq!(payload1, b"client hello");

let msg2 = server.write_message(b"server hello").unwrap();
let payload2 = client.read_message(&msg2).unwrap();
assert_eq!(payload2, b"server hello");
```

**Types:**
- `KeyPair` — Noise static key pair (X25519). Generated via `snow::Builder::generate_keypair()`.
- `Initiator` — Initiator-side handshake state machine. Writes message 1, reads message 2.
- `Responder` — Responder-side handshake state machine. Reads message 1, writes message 2.
- `Transport` — Post-handshake encrypted channel. Provides `write_message()` / `read_message()`.

**Functions:**
- `KeyPair::generate() -> Result<KeyPair, HandshakeError>` — generate X25519 static key pair
- `KeyPair::from_private_key(bytes) -> Result<KeyPair, HandshakeError>` — reconstruct from 32-byte private key
- `KeyPair::public_key() -> &[u8; 32]` — get public key bytes
- `KeyPair::private_key_bytes() -> &[u8]` — get raw private key bytes
- `Initiator::new(local_kp, remote_pub) -> Result<Initiator, HandshakeError>` — create initiator
- `Responder::new(local_kp) -> Result<Responder, HandshakeError>` — create responder
- `Initiator::write_message(payload) -> Result<Vec<u8>, HandshakeError>` — write handshake msg
- `Responder::read_message(msg) -> Result<Vec<u8>, HandshakeError>` — read handshake msg
- `Responder::remote_static_key() -> Option<[u8; 32]>` — get initiator's static key
- `Initiator::into_transport() -> Result<Transport, HandshakeError>` — transition to transport
- `Transport::write_message(plaintext) -> Result<Vec<u8>, HandshakeError>` — encrypt message
- `Transport::read_message(ciphertext) -> Result<Vec<u8>, HandshakeError>` — decrypt message

**Constants:**
- `PUBLIC_KEY_LEN = 32` — X25519 public key size in bytes

### `handshake::hybrid` — Hybrid Noise IK + ML-KEM-768 Handshake

Extends the Noise IK handshake with post-quantum security by piggybacking an
ML-KEM-768 KEM ciphertext on the first handshake message. After the 2-message
Noise exchange, both sides derive session keys from the combined classical
(Noise handshake hash) and post-quantum (KEM shared secret) contributions.

```text
Session key derivation:
  HKDF-SHA256(
    salt = noise_handshake_hash,
    ikm  = kem_shared_secret,
    info = "PhantomVPN v1" || initiator_static_pub || responder_static_pub,
    len  = 96
  )

  Output split: tx_key (32B) || rx_key (32B) || header_key (32B)
```

#### Usage

```rust
use prrr::crypto::hybrid_kex::KemKeyPair;
use prrr::handshake::noise_ik::KeyPair;
use prrr::handshake::hybrid::{HybridInitiator, HybridResponder};

// Both sides have Noise static keys; responder also has a KEM key pair
let client_noise = KeyPair::generate().unwrap();
let server_noise = KeyPair::generate().unwrap();
let server_kem = KemKeyPair::generate();
let server_kem_pub = server_kem.encapsulation_key_bytes();

// Initiator creates handshake + message 1 (includes KEM ciphertext as payload)
let (initiator, msg1) = HybridInitiator::new(
    &client_noise,
    server_noise.public_key(),
    &server_kem_pub,
).unwrap();

// Responder processes message 1, writes message 2
let responder = HybridResponder::new(&server_noise, server_kem).unwrap();
let (msg2, server_result) = responder.finish(&msg1, b"").unwrap();

// Initiator completes handshake
let client_result = initiator.finish(&msg2).unwrap();

// Both sides have identical session keys
assert_eq!(client_result.session_keys.tx_key, server_result.session_keys.tx_key);
assert_eq!(client_result.session_keys.rx_key, server_result.session_keys.rx_key);
assert_eq!(client_result.session_keys.header_key, server_result.session_keys.header_key);

```

**Types:**
- `SessionKeys` — Three 32-byte keys: `tx_key`, `rx_key`, `header_key`.
- `HybridInitiator` — Initiator-side hybrid handshake. Created with `new()`, completed with `finish()`.
- `HybridResponder` — Responder-side hybrid handshake. Created with `new()`, completed with `finish()`.
- `InitiatorResult` — Contains `session_keys`, `transport`, and `responder_payload`.
- `ResponderResult` — Contains `session_keys`, `transport`, and `initiator_static` (for identity verification).

**Key derivation:**
- `tx_key` — initiator-to-responder encryption key (bytes 0..32)
- `rx_key` — responder-to-initiator encryption key (bytes 32..64)
- `header_key` — shared header encryption key (bytes 64..96)

**Constants:**
- `SESSION_KEY_MATERIAL_LEN = 96` — total derived key material length
- `SESSION_KEY_LEN = 32` — individual key length

**Post-quantum security:** If a quantum computer breaks X25519 in the future,
the session keys remain secure because they also depend on the ML-KEM-768
shared secret. Conversely, if ML-KEM is broken, the Noise handshake hash
(derived from X25519 DH) still provides classical security.

## Error Handling

All fallible operations return `Result<T, HandshakeError>`:

```rust
use prrr::handshake::HandshakeError;

match result {
    Err(HandshakeError::MessageAuthFailed) => { /* tampered handshake message */ }
    Err(HandshakeError::NotFinished) => { /* tried transport before handshake done */ }
    Err(HandshakeError::TransportDecryptFailed) => { /* tampered transport message */ }
    Err(HandshakeError::NoiseError(msg)) => { /* internal snow error */ }
    Err(HandshakeError::KemFailed(msg)) => { /* ML-KEM operation failed */ }
    Ok(data) => { /* success */ }
}
```

## Security Notes

- Delegates Noise state machine to `snow` crate (v0.10.0, 737K downloads/month)
- No `unsafe` code (`#![deny(unsafe_code)]`)
- X25519 for DH, ChaCha20-Poly1305 for AEAD, BLAKE2s for hashing
- Initiator's static key is encrypted (identity hiding)
- Ephemeral keys provide forward secrecy
- Tampered messages are rejected via AEAD authentication
- `snow` has no formal audit but is widely deployed (libp2p, etc.)

## Architecture

### Noise IK (Classical)

```text
Initiator                     Responder
---------                     ---------
KeyPair::generate()           KeyPair::generate()
Initiator::new(kp, rs_pub)   Responder::new(kp)
    |                             |
    |-- msg1 (e, es, s, ss) ---->|
    |                             | remote_static_key() -> initiator's key
    |<--- msg2 (e, ee, se) ------|
    |                             |
into_transport()              into_transport()
    |                             |
    |== encrypted transport ======|
```

### Hybrid (Noise IK + ML-KEM-768)

```text
Initiator                          Responder
---------                          ---------
KeyPair + KemKeyPair(pub)          KeyPair + KemKeyPair
HybridInitiator::new()             HybridResponder::new()
  |  KEM encapsulate                  |
  |  Noise msg1 (payload=KEM ct)     |
  |---------------------------------->|
  |                                   | KEM decapsulate
  |                                   | remote_static_key()
  |     Noise msg2 (opt payload)      |
  |<----------------------------------|
  |                                   |
  | derive_session_keys()             | derive_session_keys()
  |   HKDF(noise_hash || kem_secret)  |   HKDF(noise_hash || kem_secret)
  |                                   |
  | SessionKeys { tx, rx, header }    | SessionKeys { tx, rx, header }
  | Transport (Noise encrypted)       | Transport (Noise encrypted)
```
