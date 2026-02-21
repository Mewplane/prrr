# Messaging Module

The `prrr::messaging` module implements the PQXDH (Post-Quantum Extended Diffie-Hellman) key agreement protocol for end-to-end encrypted messaging. It enables Alice to establish a shared secret with Bob even when Bob is offline, providing both forward secrecy and post-quantum resistance.

## Modules

### `messaging::keys` — Key Types & Prekey Bundles

Key types, prekey signing, and prekey bundle management for PQXDH.

```rust
use prrr::messaging::keys::{
    IdentityKeyPair, SignedPrekey, OneTimePrekey, PqPrekey,
    generate_prekey_bundle,
};

// Bob generates his long-term identity key
let bob_ik = IdentityKeyPair::generate();

// Bob generates prekeys
let bob_spk = SignedPrekey::generate(&bob_ik, 1);   // signed by identity key
let bob_opk = OneTimePrekey::generate(1);            // unsigned, single-use
let bob_pq = PqPrekey::generate(&bob_ik, 1);        // ML-KEM-768, signed

// Bob publishes a prekey bundle
let bundle = generate_prekey_bundle(&bob_ik, &bob_spk, Some(&bob_opk), &bob_pq);

// Bundle signatures are verifiable with identity secret key
assert!(bundle.verify(&bob_ik.secret_key_bytes()).is_ok());
```

**Types:**

| Type | Description | Signed? |
|------|-------------|---------|
| `IdentityKeyPair` | Long-term X25519 identity key with signing capability | N/A (is the signer) |
| `SignedPrekey` | Medium-term X25519 prekey bound to identity via keyed MAC | Yes |
| `OneTimePrekey` | Single-use X25519 prekey (unsigned) | No |
| `PqPrekey` | ML-KEM-768 post-quantum prekey bound to identity via keyed MAC | Yes |
| `PrekeyBundle` | Published bundle containing public keys and signatures | N/A |

**Functions:**
- `IdentityKeyPair::generate()` — generate from OS CSPRNG
- `IdentityKeyPair::sign_prekey(prekey_pub)` — produce keyed BLAKE2s MAC
- `SignedPrekey::generate(identity, id)` — generate and sign with identity key
- `OneTimePrekey::generate(id)` — generate unsigned one-time prekey
- `PqPrekey::generate(identity, id)` — generate ML-KEM-768 key and sign
- `generate_prekey_bundle(identity, spk, opk, pq)` — assemble a prekey bundle
- `PrekeyBundle::verify(ik_secret)` — verify SPK and PQ prekey signatures

**Constants:**
- `SIGNATURE_LEN = 32` — keyed BLAKE2s MAC output size
- `X25519_PUB_LEN = 32` — X25519 public key size
- `KEM_PUB_LEN = 1184` — ML-KEM-768 encapsulation key size

**Prekey Signature Scheme:**
```text
sig = BLAKE3-keyed(key=IK_secret_bytes, data="prrr-prekey-sig-v1" || prekey_pub_bytes)
```

This binds prekeys to the identity key using a keyed MAC. Only the holder of the identity secret can produce valid signatures. See FRD-014 for rationale on keyed MAC vs XEdDSA.

### `messaging::pqxdh` — PQXDH Key Agreement Protocol

PQXDH initial key agreement: Alice derives a shared secret from Bob's prekey bundle and sends an encrypted initial message. Bob derives the same secret and decrypts.

```rust
use prrr::messaging::keys::{
    IdentityKeyPair, SignedPrekey, OneTimePrekey, PqPrekey,
    generate_prekey_bundle,
};
use prrr::messaging::pqxdh;

// Bob's keys (generated earlier, bundle published to server)
let bob_ik = IdentityKeyPair::generate();
let bob_spk = SignedPrekey::generate(&bob_ik, 1);
let bob_opk = OneTimePrekey::generate(1);
let bob_pq = PqPrekey::generate(&bob_ik, 1);
let bundle = generate_prekey_bundle(&bob_ik, &bob_spk, Some(&bob_opk), &bob_pq);

// Alice initiates a session with Bob's bundle
let alice_ik = IdentityKeyPair::generate();
let result = pqxdh::initiate_session(
    &alice_ik,
    &bundle,
    &bob_ik.secret_key_bytes(),
    b"hello bob",
).unwrap();

// Bob receives the initial message and derives the same secret
let (bob_sk, plaintext) = pqxdh::respond_to_session(
    &bob_ik,
    &bob_spk,
    Some(&bob_opk),
    &bob_pq,
    &result.initial_message,
).unwrap();

assert_eq!(result.shared_secret, bob_sk);
assert_eq!(plaintext, b"hello bob");
```

**Types:**
- `InitialMessage` — Alice's initial message to Bob (IK_A, EK_A, KEM ciphertext, key IDs, AEAD ciphertext)
- `SessionInitResult` — result of `initiate_session` (shared secret, AD, initial message)
- `PqxdhError` — error enum (wraps `PrekeyError` and `CryptoError`)

**Functions:**
- `initiate_session(alice_ik, bob_bundle, bob_ik_secret, plaintext)` — Alice's side
- `respond_to_session(bob_ik, bob_spk, bob_opk, bob_pq, initial_msg)` — Bob's side

**Constants:**
- `SHARED_SECRET_LEN = 32` — derived shared secret size

## Protocol Details

### DH Operations (4 X25519 exchanges)

```text
DH1 = DH(IK_A, SPK_B)    — Alice's identity x Bob's signed prekey
DH2 = DH(EK_A, IK_B)     — Alice's ephemeral x Bob's identity
DH3 = DH(EK_A, SPK_B)    — Alice's ephemeral x Bob's signed prekey
DH4 = DH(EK_A, OPK_B)    — Alice's ephemeral x Bob's one-time prekey (optional)
```

### KEM Operation

```text
(CT, SS) = ML-KEM-768.Encapsulate(PQPK_B)
```

### Shared Secret Derivation

```text
F  = [0xFF; 32]                          — X25519 domain separator
KM = F || DH1 || DH2 || DH3 [|| DH4] || SS

SK = HKDF-SHA256(
    salt = [0x00; 32],
    ikm  = KM,
    info = "prrr-pqxdh-v1",
    len  = 32
)
```

### Associated Data

```text
AD = IK_A_pub (32 bytes) || IK_B_pub (32 bytes) || PQPK_B_pub (1184 bytes)
```

### Initial Message Encryption

```text
ciphertext = ChaCha20-Poly1305(key=SK, nonce=[0x00;12], plain=payload, aad=AD)
```

### `messaging::ratchet` — Double Ratchet with Sparse PQ Ratchet (SPQR)

Ongoing message encryption using the Double Ratchet algorithm extended with periodic ML-KEM-768 post-quantum ratchet steps.

```rust
use prrr::messaging::ratchet::{RatchetState, RatchetConfig};
use prrr::messaging::keys::{IdentityKeyPair, SignedPrekey, PqPrekey, OneTimePrekey, generate_prekey_bundle};
use prrr::messaging::pqxdh;
use prrr::crypto::x25519;

// After PQXDH completes, both sides have a shared secret.
// Alice initializes her ratchet with Bob's signed prekey as his initial DH key.
let shared_secret = [0xABu8; 32]; // from PQXDH
let bob_dh = x25519::KeyPair::generate();
let bob_dh_pub = bob_dh.public_key_bytes();

let mut alice = RatchetState::init_alice(
    shared_secret,
    bob_dh_pub,
    RatchetConfig::default(),
).unwrap();

let mut bob = RatchetState::init_bob(
    shared_secret,
    bob_dh,
    RatchetConfig::default(),
);

// Alice sends a message
let (header, ciphertext) = alice.encrypt(b"hello bob").unwrap();
let plaintext = bob.decrypt(&header, &ciphertext).unwrap();
assert_eq!(plaintext, b"hello bob");

// Bob replies (triggers DH ratchet)
let (header, ciphertext) = bob.encrypt(b"hello alice").unwrap();
let plaintext = alice.decrypt(&header, &ciphertext).unwrap();
assert_eq!(plaintext, b"hello alice");
```

**Types:**

| Type | Description |
|------|-------------|
| `RatchetState` | Double Ratchet state machine for ongoing message encryption |
| `RatchetConfig` | Configuration: `max_skip` (default 256), `pq_ratchet_interval` (default 128) |
| `MessageHeader` | Header sent with each message (DH pub, prev count, msg number, optional PQ data) |
| `PqRatchetData` | KEM ciphertext + new encapsulation key for SPQR steps |
| `RatchetError` | Error enum: `DecryptionFailed`, `MaxSkipExceeded`, `Crypto`, `NoReceivingChain` |

**Functions:**
- `RatchetState::init_alice(shared_secret, bob_dh_pub, config)` — initialize Alice's ratchet after PQXDH
- `RatchetState::init_bob(shared_secret, bob_dh_keypair, config)` — initialize Bob's ratchet after PQXDH
- `RatchetState::encrypt(plaintext)` — encrypt a message, returns `(MessageHeader, ciphertext)`
- `RatchetState::decrypt(header, ciphertext)` — decrypt a message, performing DH ratchet if needed

**KDF Functions (internal):**

| Function | Formula | Output |
|----------|---------|--------|
| KDF_RK | `HKDF-SHA256(salt=root_key, ikm=dh_output[\|\|kem_ss], info="prrr-ratchet-rk-v1", len=64)` | (new_root_key, chain_key) |
| KDF_CK | `HMAC-SHA256(key=chain_key, msg=0x01)` / `HMAC-SHA256(key=chain_key, msg=0x02)` | (message_key, next_chain_key) |
| Message key | `HKDF-SHA256(salt=[0x00;32], ikm=msg_key, info="prrr-ratchet-msg-v1", len=44)` | (enc_key[32], nonce[12]) |

**Sparse PQ Ratchet (SPQR):**

Every N DH ratchet steps (configurable, default 128), the sender performs an ML-KEM-768 encapsulation against the remote's encapsulation key. The resulting shared secret is mixed directly into the `kdf_rk` derivation alongside the DH output (`ikm = dh_output || kem_ss`), ensuring both sides derive identical chain keys at the same DH ratchet boundary.

**Out-of-Order Message Handling:**

Skipped message keys are cached in a bounded HashMap keyed by `(dh_public, msg_number)`. When a message arrives with a higher number than expected, keys for intermediate messages are pre-derived and stored. Messages can then be decrypted out of order until the cache limit (`max_skip`, default 256) is reached.

**Message Header Wire Format:**
```text
[32 bytes: DH public key]
[ 4 bytes: prev_count (BE)]
[ 4 bytes: msg_number (BE)]
[ 1 byte:  flags (bit 0 = PQ data present)]
[optional: 1088 bytes KEM ciphertext + 1184 bytes KEM encapsulation key]
```

### `messaging::types` — Wire Message Format

Serializable envelope format for messages exchanged between clients and the relay server.

**Types:**

| Type | Description |
|------|-------------|
| `WireMessage` | Wire envelope: sender_id, msg_id, type-discriminated payload |
| `WirePayload` | Enum: `Data(DataPayload)`, `Ack(AckPayload)`, `Fetch` |
| `DataPayload` | Recipient ID + `EncryptedEnvelope` (ratchet header + ciphertext) |
| `AckPayload` | Acknowledged message ID (16 bytes) |
| `EncryptedEnvelope` | Ratchet header bytes + AEAD ciphertext |
| `MessageType` | Enum: Data (0x01), Ack (0x02), Fetch (0x03) |
| `WireError` | Error enum: TooShort, UnsupportedVersion, UnknownType, InvalidFormat |

**Wire Format:**
```text
[1 byte: version (0x01)]
[1 byte: msg_type]
[32 bytes: sender_id (X25519 pub)]
[16 bytes: msg_id (random)]
[variable: payload]
```

**Constants:**
- `PROTOCOL_VERSION = 0x01`
- `MSG_ID_LEN = 16` — random unique message identifier
- `PEER_ID_LEN = 32` — X25519 public key
- `MIN_WIRE_LEN = 50` — minimum wire message size

### `messaging::relay` — Server-Side Message Relay

In-memory store-and-forward relay with per-peer bounded queues and deduplication.

```rust
use prrr::messaging::relay::{MessageRelay, RelayConfig};

let mut relay = MessageRelay::new(RelayConfig {
    max_queue_size: 1000,  // per-peer queue limit
    max_seen_ids: 10_000,  // deduplication window
});

// Enqueue a message for a recipient
relay.enqueue(recipient_id, wire_message)?;

// Recipient connects — dequeue all pending messages (FIFO)
let pending = relay.dequeue(&recipient_id);

// Recipient acknowledges delivery
relay.ack(&recipient_id, &msg_id);
```

**Features:**
- Per-peer bounded queues (default max 1000 messages)
- FIFO delivery ordering
- Deduplication by message ID with LRU eviction (default window 10,000)
- Queue overflow drops oldest message
- Acknowledgment removes specific message from queue

### `messaging::transport` — Message Transport

Sends/receives `WireMessage` over byte-oriented channels. Transport-agnostic — works with MASQUE datagrams, channels, or any byte sender/receiver.

```rust
use prrr::messaging::transport::{MessageTransport, channel_pair};

// Create a paired channel transport for testing
let (transport_a, transport_b) = channel_pair(16);

// Send a wire message
transport_a.send(&wire_msg)?;

// Receive a wire message
let received = transport_b.recv().await?;
```

**Traits:**
- `MessageSender` — `fn send(&self, data: &[u8]) -> Result<()>`
- `MessageReceiver` — `async fn recv(&self) -> Result<Vec<u8>>`

### `messaging::client` — High-Level Messaging Client

Orchestrates the full send/receive lifecycle: session management, ratchet encryption/decryption, wire serialization.

```rust
use prrr::messaging::client::{MessagingClient, create_session_pair};
use prrr::messaging::ratchet::RatchetConfig;

// Create paired clients with pre-established sessions
let shared_secret = [0xAB; 32]; // from PQXDH
let (mut alice, mut bob) = create_session_pair(
    alice_id, bob_id, shared_secret, RatchetConfig::default(),
)?;

// Alice sends a message
let wire_msg = alice.prepare_message(&bob_id, b"hello bob")?;

// Bob decrypts
let (sender, plaintext) = bob.process_incoming(&wire_msg)?;
assert_eq!(plaintext, b"hello bob");

// Bob sends acknowledgment
let ack = bob.create_ack(&wire_msg);

// Bob requests queued messages from relay
let fetch = bob.create_fetch();
```

**Functions:**
- `MessagingClient::new(identity, config)` — create client with identity
- `MessagingClient::add_session(peer_id, ratchet_state)` — register session
- `MessagingClient::prepare_message(peer_id, plaintext)` — encrypt and wrap
- `MessagingClient::process_incoming(wire_msg)` — decrypt and extract
- `MessagingClient::create_ack(original_msg)` — create acknowledgment
- `MessagingClient::create_fetch()` — create fetch request
- `create_session_pair(alice_id, bob_id, shared_secret, config)` — test helper

## Security Properties

- **Forward secrecy**: ephemeral key EK_A ensures past sessions remain secure if long-term keys are compromised
- **Post-quantum resistance**: ML-KEM-768 KEM contribution protects against quantum "harvest now, decrypt later" attacks
- **Offline initiation**: Alice can establish a session using Bob's prekey bundle without Bob being online
- **OPK depletion tolerance**: protocol works without OPK (DH4 is omitted), at the cost of reduced forward secrecy for the initial message
- **Per-message forward secrecy**: each message uses a unique message key derived from the symmetric ratchet; chain keys are overwritten after each step
- **Break-in recovery**: DH ratchet step on every direction change generates fresh key material; compromised state heals within one round-trip
- **Post-quantum ongoing secrecy**: Sparse PQ Ratchet (SPQR) periodically mixes ML-KEM-768 shared secret into root key derivation, protecting against future quantum computers
- **Out-of-order resilience**: skipped message keys are cached (bounded by `max_skip`) to handle reordered delivery without breaking the ratchet
- **At-least-once delivery**: relay queues messages for offline recipients; acknowledgments confirm delivery
- **Deduplication**: relay tracks seen message IDs to prevent duplicate processing
- **Bounded queues**: per-peer queue limits prevent memory exhaustion on the relay server

## Security Notes

- All secret key material uses types that implement `Zeroize` on drop
- Prekey signatures use constant-time comparison via the `subtle` crate
- ML-KEM uses implicit rejection (wrong ciphertext produces pseudorandom secret, detected via AEAD failure)
- No `unsafe` code (`#![deny(unsafe_code)]`)
- Keyed BLAKE2s MAC is sufficient for PRRR's single-server trust model; a federated model would require XEdDSA public-key signatures

## Error Handling

```rust
use prrr::messaging::keys::PrekeyError;
use prrr::messaging::pqxdh::PqxdhError;

match result {
    Err(PqxdhError::PrekeyVerification(PrekeyError::InvalidSpkSignature)) => {
        /* SPK signature invalid */
    }
    Err(PqxdhError::PrekeyVerification(PrekeyError::InvalidPqSignature)) => {
        /* PQ prekey signature invalid */
    }
    Err(PqxdhError::Crypto(e)) => { /* cryptographic operation failed */ }
    Ok(data) => { /* success */ }
}
```
