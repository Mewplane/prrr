// FRD: specs/frds/FRD-004.md

//! Hybrid Noise IK + ML-KEM-768 handshake.
//!
//! Extends the Noise IK handshake (F-003) with post-quantum security by
//! piggybacking an ML-KEM-768 ciphertext on the first handshake message
//! payload. After the 2-message Noise exchange, both sides derive session
//! keys from the combination of the Noise handshake hash and the KEM
//! shared secret:
//!
//! ```text
//! session_keys = HKDF-SHA256(
//!     salt  = noise_handshake_hash,
//!     ikm   = kem_shared_secret,
//!     info  = "PhantomVPN v1" || initiator_static_pub || responder_static_pub,
//!     len   = 96
//! )
//! ```
//!
//! The 96-byte output is split into:
//! - `tx_key`     (bytes 0..32)  — initiator-to-responder encryption key
//! - `rx_key`     (bytes 32..64) — responder-to-initiator encryption key
//! - `header_key` (bytes 64..96) — shared header encryption key

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    HandshakeError,
    noise_ik::{self, Initiator, KeyPair, PUBLIC_KEY_LEN, Responder, Transport},
};
use crate::crypto::{
    hybrid_kex::{self, KEM_CIPHERTEXT_LEN, KemKeyPair},
    kdf,
};

/// HKDF info prefix for session key derivation per SPEC.md.
const SESSION_KEY_INFO_PREFIX: &[u8] = b"PhantomVPN v1";

/// Total byte length of derived session key material (tx + rx + header).
pub const SESSION_KEY_MATERIAL_LEN: usize = 96;

/// Byte length of each individual session key.
pub const SESSION_KEY_LEN: usize = 32;

/// Session keys derived from the hybrid handshake.
///
/// Contains three 32-byte keys: `tx_key` (initiator→responder),
/// `rx_key` (responder→initiator), and `header_key` (shared).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Encryption key for the initiator-to-responder direction.
    pub tx_key: [u8; SESSION_KEY_LEN],
    /// Encryption key for the responder-to-initiator direction.
    pub rx_key: [u8; SESSION_KEY_LEN],
    /// Shared header encryption key.
    pub header_key: [u8; SESSION_KEY_LEN],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("tx_key", &"[redacted]")
            .field("rx_key", &"[redacted]")
            .field("header_key", &"[redacted]")
            .finish()
    }
}

/// Derive session keys from the Noise handshake hash and KEM shared secret.
///
/// Uses the SPEC.md formula:
/// ```text
/// HKDF-SHA256(salt=handshake_hash, ikm=kem_secret, info=prefix||init_pub||resp_pub, len=96)
/// ```
///
/// The 96 bytes are split into `tx_key`, `rx_key`, and `header_key`.
fn derive_session_keys(
    handshake_hash: &[u8],
    kem_shared_secret: &[u8; SESSION_KEY_LEN],
    initiator_static: &[u8; PUBLIC_KEY_LEN],
    responder_static: &[u8; PUBLIC_KEY_LEN],
) -> Result<SessionKeys, HandshakeError> {
    let mut info = Vec::with_capacity(SESSION_KEY_INFO_PREFIX.len() + PUBLIC_KEY_LEN + PUBLIC_KEY_LEN);
    info.extend_from_slice(SESSION_KEY_INFO_PREFIX);
    info.extend_from_slice(initiator_static);
    info.extend_from_slice(responder_static);

    let prk = kdf::extract(handshake_hash, kem_shared_secret);
    let okm = kdf::expand(&prk, &info, SESSION_KEY_MATERIAL_LEN).map_err(|e| HandshakeError::KemFailed(e.to_string()))?;

    let mut tx_key = [0u8; SESSION_KEY_LEN];
    let mut rx_key = [0u8; SESSION_KEY_LEN];
    let mut header_key = [0u8; SESSION_KEY_LEN];

    tx_key.copy_from_slice(&okm[..SESSION_KEY_LEN]);
    rx_key.copy_from_slice(&okm[SESSION_KEY_LEN..SESSION_KEY_LEN * 2]);
    header_key.copy_from_slice(&okm[SESSION_KEY_LEN * 2..]);

    Ok(SessionKeys {
        tx_key,
        rx_key,
        header_key,
    })
}

/// Result of a completed hybrid handshake on the initiator side.
pub struct InitiatorResult {
    /// Derived session keys (tx = initiator→responder).
    pub session_keys: SessionKeys,
    /// Noise transport for encrypted message exchange.
    pub transport: Transport,
    /// Payload received from the responder in Noise message 2.
    pub responder_payload: Vec<u8>,
}

/// Result of a completed hybrid handshake on the responder side.
pub struct ResponderResult {
    /// Derived session keys (tx = initiator→responder, rx = responder→initiator).
    ///
    /// Note: the responder should use `rx_key` for sending and `tx_key` for
    /// receiving, since `tx_key` is the initiator→responder direction.
    pub session_keys: SessionKeys,
    /// Noise transport for encrypted message exchange.
    pub transport: Transport,
    /// The initiator's Noise static public key (for identity verification).
    pub initiator_static: [u8; PUBLIC_KEY_LEN],
}

/// Initiator-side hybrid handshake state.
pub struct HybridInitiator {
    noise: Initiator,
    kem_shared_secret: [u8; SESSION_KEY_LEN],
    initiator_static: [u8; PUBLIC_KEY_LEN],
    responder_static: [u8; PUBLIC_KEY_LEN],
}

impl HybridInitiator {
    /// Create a new hybrid handshake initiator.
    ///
    /// `noise_keypair` is the initiator's Noise static key.
    /// `responder_noise_pub` is the responder's known Noise static public key.
    /// `responder_kem_pub` is the responder's ML-KEM-768 encapsulation key bytes.
    pub fn new(
        noise_keypair: &KeyPair,
        responder_noise_pub: &[u8; PUBLIC_KEY_LEN],
        responder_kem_pub: &[u8],
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        // KEM encapsulate against responder's KEM public key
        let (kem_ciphertext, kem_shared) =
            hybrid_kex::kem_encapsulate(responder_kem_pub).map_err(|e| HandshakeError::KemFailed(e.to_string()))?;

        // Build Noise IK initiator
        let mut noise = noise_ik::Initiator::new(noise_keypair, responder_noise_pub)?;

        // Write Noise message 1 with KEM ciphertext as payload
        let msg1 = noise.write_message(&kem_ciphertext)?;

        let initiator = Self {
            noise,
            kem_shared_secret: kem_shared,
            initiator_static: *noise_keypair.public_key(),
            responder_static: *responder_noise_pub,
        };

        Ok((initiator, msg1))
    }

    /// Complete the hybrid handshake by reading the responder's message 2.
    ///
    /// Returns the `InitiatorResult` containing session keys, Noise
    /// transport, and the responder's optional payload.
    pub fn finish(mut self, msg2: &[u8]) -> Result<InitiatorResult, HandshakeError> {
        let responder_payload = self.noise.read_message(msg2)?;

        let handshake_hash = self.noise.handshake_hash()?;
        let session_keys = derive_session_keys(
            &handshake_hash,
            &self.kem_shared_secret,
            &self.initiator_static,
            &self.responder_static,
        )?;
        let transport = self.noise.into_transport()?;

        Ok(InitiatorResult {
            session_keys,
            transport,
            responder_payload,
        })
    }
}

/// Responder-side hybrid handshake state.
pub struct HybridResponder {
    noise: Responder,
    kem_keypair: KemKeyPair,
    responder_static: [u8; PUBLIC_KEY_LEN],
}

impl HybridResponder {
    /// Create a new hybrid handshake responder.
    ///
    /// `noise_keypair` is the responder's Noise static key.
    /// `kem_keypair` is the responder's ML-KEM-768 key pair.
    pub fn new(noise_keypair: &KeyPair, kem_keypair: KemKeyPair) -> Result<Self, HandshakeError> {
        let noise = noise_ik::Responder::new(noise_keypair)?;
        Ok(Self {
            noise,
            kem_keypair,
            responder_static: *noise_keypair.public_key(),
        })
    }

    /// Process the initiator's message 1, write message 2, and complete
    /// the hybrid handshake.
    ///
    /// `responder_payload` is an optional payload to include in message 2.
    ///
    /// Returns `(message2_bytes, ResponderResult)`.
    pub fn finish(mut self, msg1: &[u8], responder_payload: &[u8]) -> Result<(Vec<u8>, ResponderResult), HandshakeError> {
        // Read Noise message 1 — payload contains KEM ciphertext
        let kem_ciphertext = self.noise.read_message(msg1)?;

        // Validate KEM ciphertext length
        if kem_ciphertext.len() != KEM_CIPHERTEXT_LEN {
            return Err(HandshakeError::KemFailed(format!(
                "invalid KEM ciphertext length: expected {KEM_CIPHERTEXT_LEN}, got {}",
                kem_ciphertext.len()
            )));
        }

        // Decapsulate KEM shared secret
        let kem_shared = self
            .kem_keypair
            .decapsulate(&kem_ciphertext)
            .map_err(|e| HandshakeError::KemFailed(e.to_string()))?;

        // Retrieve initiator's Noise static key (available after reading msg1)
        let initiator_static = self
            .noise
            .remote_static_key()
            .ok_or_else(|| HandshakeError::KemFailed("initiator static key not available".to_string()))?;

        // Write Noise message 2
        let msg2 = self.noise.write_message(responder_payload)?;

        let handshake_hash = self.noise.handshake_hash()?;
        let session_keys = derive_session_keys(&handshake_hash, &kem_shared, &initiator_static, &self.responder_static)?;
        let transport = self.noise.into_transport()?;

        Ok((
            msg2,
            ResponderResult {
                session_keys,
                transport,
                initiator_static,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-1: Full hybrid handshake round-trip: both sides derive identical SessionKeys
    #[test]
    fn hybrid_handshake_round_trip() {
        let initiator_noise = KeyPair::generate().expect("initiator noise keypair");
        let responder_noise = KeyPair::generate().expect("responder noise keypair");
        let responder_kem = KemKeyPair::generate();
        let responder_kem_pub = responder_kem.encapsulation_key_bytes();

        let (initiator, msg1) =
            HybridInitiator::new(&initiator_noise, responder_noise.public_key(), &responder_kem_pub).expect("initiator");

        let responder = HybridResponder::new(&responder_noise, responder_kem).expect("responder");
        let (msg2, resp_result) = responder.finish(&msg1, b"").expect("responder finish");

        let init_result = initiator.finish(&msg2).expect("initiator finish");

        // Both sides derive identical session keys
        assert_eq!(init_result.session_keys.tx_key, resp_result.session_keys.tx_key);
        assert_eq!(init_result.session_keys.rx_key, resp_result.session_keys.rx_key);
        assert_eq!(init_result.session_keys.header_key, resp_result.session_keys.header_key);
    }

    // T-2: tx/rx key directionality — they are different from each other
    #[test]
    fn session_keys_tx_rx_differ() {
        let initiator_noise = KeyPair::generate().expect("initiator noise keypair");
        let responder_noise = KeyPair::generate().expect("responder noise keypair");
        let responder_kem = KemKeyPair::generate();
        let responder_kem_pub = responder_kem.encapsulation_key_bytes();

        let (initiator, msg1) =
            HybridInitiator::new(&initiator_noise, responder_noise.public_key(), &responder_kem_pub).expect("initiator");

        let responder = HybridResponder::new(&responder_noise, responder_kem).expect("responder");
        let (msg2, resp_result) = responder.finish(&msg1, b"").expect("responder finish");

        let init_result = initiator.finish(&msg2).expect("initiator finish");

        // tx_key and rx_key should be different (different directions)
        assert_ne!(init_result.session_keys.tx_key, init_result.session_keys.rx_key);
        // header_key should differ from both
        assert_ne!(init_result.session_keys.header_key, init_result.session_keys.tx_key);
        assert_ne!(init_result.session_keys.header_key, init_result.session_keys.rx_key);

        // Verify keys are non-zero
        assert_ne!(resp_result.session_keys.tx_key, [0u8; SESSION_KEY_LEN]);
    }

    // T-3: Noise transport still works after hybrid handshake
    #[test]
    fn noise_transport_works_after_hybrid() {
        let initiator_noise = KeyPair::generate().expect("initiator noise keypair");
        let responder_noise = KeyPair::generate().expect("responder noise keypair");
        let responder_kem = KemKeyPair::generate();
        let responder_kem_pub = responder_kem.encapsulation_key_bytes();

        let (initiator, msg1) =
            HybridInitiator::new(&initiator_noise, responder_noise.public_key(), &responder_kem_pub).expect("initiator");

        let responder = HybridResponder::new(&responder_noise, responder_kem).expect("responder");
        let (msg2, mut resp_result) = responder.finish(&msg1, b"").expect("responder finish");

        let mut init_result = initiator.finish(&msg2).expect("initiator finish");

        // Initiator → Responder via Noise transport
        let plaintext = b"post-hybrid message";
        let ct = init_result.transport.write_message(plaintext).expect("encrypt");
        let pt = resp_result.transport.read_message(&ct).expect("decrypt");
        assert_eq!(pt, plaintext);

        // Responder → Initiator
        let reply = b"reply from responder";
        let ct = resp_result.transport.write_message(reply).expect("encrypt");
        let pt = init_result.transport.read_message(&ct).expect("decrypt");
        assert_eq!(pt, reply);
    }

    // T-4: Responder retrieves initiator's Noise static key
    #[test]
    fn responder_gets_initiator_identity() {
        let initiator_noise = KeyPair::generate().expect("initiator noise keypair");
        let responder_noise = KeyPair::generate().expect("responder noise keypair");
        let responder_kem = KemKeyPair::generate();
        let responder_kem_pub = responder_kem.encapsulation_key_bytes();

        let (initiator, msg1) =
            HybridInitiator::new(&initiator_noise, responder_noise.public_key(), &responder_kem_pub).expect("initiator");

        let responder = HybridResponder::new(&responder_noise, responder_kem).expect("responder");
        let (msg2, resp_result) = responder.finish(&msg1, b"").expect("responder finish");

        let _init_result = initiator.finish(&msg2).expect("initiator finish");

        assert_eq!(resp_result.initiator_static, *initiator_noise.public_key());
    }

    // T-5: Different KEM keypairs → different session keys
    #[test]
    fn different_kem_keys_different_session_keys() {
        let initiator_noise = KeyPair::generate().expect("initiator noise keypair");
        let responder_noise = KeyPair::generate().expect("responder noise keypair");

        // First handshake with KEM keypair A
        let kem_a = KemKeyPair::generate();
        let kem_a_pub = kem_a.encapsulation_key_bytes();
        let (init_a, msg1_a) = HybridInitiator::new(&initiator_noise, responder_noise.public_key(), &kem_a_pub).expect("initiator a");
        let resp_a = HybridResponder::new(&responder_noise, kem_a).expect("responder a");
        let (msg2_a, resp_result_a) = resp_a.finish(&msg1_a, b"").expect("responder a finish");
        let init_result_a = init_a.finish(&msg2_a).expect("initiator a finish");

        // Second handshake with KEM keypair B
        let kem_b = KemKeyPair::generate();
        let kem_b_pub = kem_b.encapsulation_key_bytes();
        let (init_b, msg1_b) = HybridInitiator::new(&initiator_noise, responder_noise.public_key(), &kem_b_pub).expect("initiator b");
        let resp_b = HybridResponder::new(&responder_noise, kem_b).expect("responder b");
        let (msg2_b, resp_result_b) = resp_b.finish(&msg1_b, b"").expect("responder b finish");
        let init_result_b = init_b.finish(&msg2_b).expect("initiator b finish");

        // Session keys should differ (different KEM secrets + different Noise ephemeral keys)
        assert_ne!(init_result_a.session_keys.tx_key, init_result_b.session_keys.tx_key);
        assert_ne!(resp_result_a.session_keys.tx_key, resp_result_b.session_keys.tx_key);
    }

    // T-6: Invalid KEM ciphertext length in payload → error
    #[test]
    fn invalid_kem_ciphertext_length_fails() {
        let initiator_noise = KeyPair::generate().expect("initiator noise keypair");
        let responder_noise = KeyPair::generate().expect("responder noise keypair");
        let responder_kem = KemKeyPair::generate();

        // Create a Noise-only handshake with a short payload (not valid KEM ciphertext)
        let mut noise_init = noise_ik::Initiator::new(&initiator_noise, responder_noise.public_key()).expect("noise initiator");

        let short_payload = b"not a kem ciphertext";
        let msg1 = noise_init.write_message(short_payload).expect("write msg1");

        let hybrid_resp = HybridResponder::new(&responder_noise, responder_kem).expect("hybrid responder");
        let result = hybrid_resp.finish(&msg1, b"");

        match result {
            Err(HandshakeError::KemFailed(msg)) => {
                assert!(msg.contains("invalid KEM ciphertext length"), "error should mention length: {msg}");
            }
            Err(other) => panic!("expected KemFailed, got: {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    // T-7: Tampered KEM ciphertext → session keys mismatch
    #[test]
    fn tampered_kem_ciphertext_causes_key_mismatch() {
        let initiator_noise = KeyPair::generate().expect("initiator noise keypair");
        let responder_noise = KeyPair::generate().expect("responder noise keypair");
        let responder_kem = KemKeyPair::generate();
        let responder_kem_pub = responder_kem.encapsulation_key_bytes();

        // Initiator encapsulates against correct KEM key
        let (kem_ciphertext, initiator_kem_secret) = hybrid_kex::kem_encapsulate(&responder_kem_pub).expect("kem encapsulate");

        // Tamper the KEM ciphertext
        let mut tampered_ct = kem_ciphertext.clone();
        tampered_ct[0] ^= 0xff;

        // Initiator sends tampered KEM ciphertext as Noise payload
        let mut noise_init = noise_ik::Initiator::new(&initiator_noise, responder_noise.public_key()).expect("noise initiator");
        let msg1 = noise_init.write_message(&tampered_ct).expect("write msg1");

        // Responder processes with real KEM keypair
        let hybrid_resp = HybridResponder::new(&responder_noise, responder_kem).expect("hybrid responder");
        let (msg2, resp_result) = hybrid_resp.finish(&msg1, b"").expect("responder finish");

        // Initiator finishes Noise handshake
        noise_init.read_message(&msg2).expect("read msg2");
        let handshake_hash_bytes = noise_init.handshake_hash().expect("handshake hash");

        // Initiator derives session keys with its (correct) KEM secret
        let init_session_keys = derive_session_keys(
            &handshake_hash_bytes,
            &initiator_kem_secret,
            initiator_noise.public_key(),
            responder_noise.public_key(),
        )
        .expect("derive session keys");

        // ML-KEM implicit rejection: responder gets a different (pseudorandom) secret
        // So session keys MUST differ
        assert_ne!(init_session_keys.tx_key, resp_result.session_keys.tx_key);
    }

    // T-8: Session key derivation is deterministic (same inputs → same keys)
    #[test]
    fn session_key_derivation_deterministic() {
        let handshake_hash = [0x42u8; SESSION_KEY_LEN];
        let kem_secret = [0x99u8; SESSION_KEY_LEN];
        let init_pub = [0x01u8; PUBLIC_KEY_LEN];
        let resp_pub = [0x02u8; PUBLIC_KEY_LEN];

        let keys1 = derive_session_keys(&handshake_hash, &kem_secret, &init_pub, &resp_pub).expect("derive 1");
        let keys2 = derive_session_keys(&handshake_hash, &kem_secret, &init_pub, &resp_pub).expect("derive 2");

        assert_eq!(keys1.tx_key, keys2.tx_key);
        assert_eq!(keys1.rx_key, keys2.rx_key);
        assert_eq!(keys1.header_key, keys2.header_key);

        // Different handshake hash → different keys
        let different_hash = [0x43u8; SESSION_KEY_LEN];
        let keys3 = derive_session_keys(&different_hash, &kem_secret, &init_pub, &resp_pub).expect("derive 3");
        assert_ne!(keys1.tx_key, keys3.tx_key);
    }

    // T-9: Multiple hybrid handshakes produce different session keys
    #[test]
    fn multiple_handshakes_different_keys() {
        let initiator_noise = KeyPair::generate().expect("initiator noise keypair");
        let responder_noise = KeyPair::generate().expect("responder noise keypair");

        let kem1 = KemKeyPair::generate();
        let kem1_pub = kem1.encapsulation_key_bytes();
        let (init1, msg1_a) = HybridInitiator::new(&initiator_noise, responder_noise.public_key(), &kem1_pub).expect("init 1");
        let resp1 = HybridResponder::new(&responder_noise, kem1).expect("resp 1");
        let (msg2_a, _) = resp1.finish(&msg1_a, b"").expect("resp 1 finish");
        let result1 = init1.finish(&msg2_a).expect("init 1 finish");

        let kem2 = KemKeyPair::generate();
        let kem2_pub = kem2.encapsulation_key_bytes();
        let (init2, msg1_b) = HybridInitiator::new(&initiator_noise, responder_noise.public_key(), &kem2_pub).expect("init 2");
        let resp2 = HybridResponder::new(&responder_noise, kem2).expect("resp 2");
        let (msg2_b, _) = resp2.finish(&msg1_b, b"").expect("resp 2 finish");
        let result2 = init2.finish(&msg2_b).expect("init 2 finish");

        // Different ephemeral keys + different KEM → different session keys
        assert_ne!(result1.session_keys.tx_key, result2.session_keys.tx_key);
    }

    // T-10: Integration: full hybrid handshake + transport message exchange
    #[test]
    fn integration_hybrid_handshake_and_transport() {
        let initiator_noise = KeyPair::generate().expect("initiator noise keypair");
        let responder_noise = KeyPair::generate().expect("responder noise keypair");
        let responder_kem = KemKeyPair::generate();
        let responder_kem_pub = responder_kem.encapsulation_key_bytes();

        let (initiator, msg1) =
            HybridInitiator::new(&initiator_noise, responder_noise.public_key(), &responder_kem_pub).expect("initiator");

        let responder = HybridResponder::new(&responder_noise, responder_kem).expect("responder");
        let (msg2, mut resp_result) = responder.finish(&msg1, b"").expect("responder finish");

        let mut init_result = initiator.finish(&msg2).expect("initiator finish");

        // Session keys match
        assert_eq!(init_result.session_keys.tx_key, resp_result.session_keys.tx_key);

        // Exchange multiple messages via Noise transport
        let message_count: usize = 10;
        for i in 0..message_count {
            let msg = format!("hybrid transport message {i}");
            let ct = init_result.transport.write_message(msg.as_bytes()).expect("encrypt");
            let pt = resp_result.transport.read_message(&ct).expect("decrypt");
            assert_eq!(pt, msg.as_bytes());
        }
    }

    // T-11: Responder payload in message 2 delivered correctly
    #[test]
    fn responder_payload_delivered() {
        let initiator_noise = KeyPair::generate().expect("initiator noise keypair");
        let responder_noise = KeyPair::generate().expect("responder noise keypair");
        let responder_kem = KemKeyPair::generate();
        let responder_kem_pub = responder_kem.encapsulation_key_bytes();

        let expected_payload = b"server certificate data";

        let (initiator, msg1) =
            HybridInitiator::new(&initiator_noise, responder_noise.public_key(), &responder_kem_pub).expect("initiator");

        let responder = HybridResponder::new(&responder_noise, responder_kem).expect("responder");
        let (msg2, _resp_result) = responder.finish(&msg1, expected_payload).expect("responder finish");

        let init_result = initiator.finish(&msg2).expect("initiator finish");

        assert_eq!(init_result.responder_payload, expected_payload);
    }

    // T-12 (FRD-017): SessionKeys zeroize clears all key material
    #[test]
    fn session_keys_zeroize_clears_fields() {
        let mut keys = SessionKeys {
            tx_key: [0xAA; SESSION_KEY_LEN],
            rx_key: [0xBB; SESSION_KEY_LEN],
            header_key: [0xCC; SESSION_KEY_LEN],
        };

        // Verify keys are non-zero before zeroize
        assert_ne!(keys.tx_key, [0u8; SESSION_KEY_LEN]);
        assert_ne!(keys.rx_key, [0u8; SESSION_KEY_LEN]);
        assert_ne!(keys.header_key, [0u8; SESSION_KEY_LEN]);

        keys.zeroize();

        assert_eq!(keys.tx_key, [0u8; SESSION_KEY_LEN]);
        assert_eq!(keys.rx_key, [0u8; SESSION_KEY_LEN]);
        assert_eq!(keys.header_key, [0u8; SESSION_KEY_LEN]);
    }
}
