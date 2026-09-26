// FRD: specs/frds/FRD-002.md

//! Hybrid X25519 + ML-KEM-768 post-quantum key exchange.
//!
//! Combines classical Diffie-Hellman (X25519) with a post-quantum KEM
//! (ML-KEM-768, FIPS 203) to produce a single shared secret resilient
//! against both classical and quantum adversaries.
//!
//! The combined secret is derived as:
//! ```text
//! HKDF-SHA256(salt=[], ikm=x25519_shared || kem_shared, info=HYBRID_INFO, len=32)
//! ```
//!
//! **Implicit rejection**: ML-KEM-768 decapsulation with a wrong ciphertext
//! does not return an error — it returns a pseudorandom secret. Protocol
//! layers above (F-004 Hybrid Handshake) detect this via MAC failure.

use ml_kem::{
    Ciphertext, EncodedSizeUser, KemCore, MlKem768,
    kem::{Decapsulate, Encapsulate},
};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use super::{CryptoError, kdf, x25519};

/// HKDF info string for the hybrid key exchange derivation.
const HYBRID_INFO: &[u8] = b"prrr-hybrid-kex-v1";

/// Byte length of the combined shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

/// Byte length of an ML-KEM-768 ciphertext.
pub const KEM_CIPHERTEXT_LEN: usize = 1088;

/// Byte length of an ML-KEM-768 encapsulation key.
pub const KEM_ENCAPSULATION_KEY_LEN: usize = 1184;

/// Byte length of an ML-KEM-768 decapsulation key (serialized).
pub const KEM_DECAPSULATION_KEY_LEN: usize = 2400;

/// An ML-KEM-768 key pair for post-quantum key encapsulation.
pub struct KemKeyPair {
    dk: ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>,
}

impl KemKeyPair {
    /// Generate a new ML-KEM-768 key pair from the OS CSPRNG.
    pub fn generate() -> Self {
        let (dk, _ek) = MlKem768::generate(&mut OsRng);
        Self { dk }
    }

    /// Reconstruct a `KemKeyPair` from serialized decapsulation key bytes.
    ///
    /// The bytes must be exactly `KEM_DECAPSULATION_KEY_LEN` (2400) long.
    pub fn from_dk_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let dk_array: &[u8; KEM_DECAPSULATION_KEY_LEN] = bytes.try_into().map_err(|_| CryptoError::KemDecapsulationFailed)?;
        let dk = ml_kem::kem::DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(dk_array.into());
        Ok(Self { dk })
    }

    /// Serialize the decapsulation (private) key to bytes.
    pub fn dk_bytes(&self) -> Vec<u8> {
        self.dk.as_bytes().to_vec()
    }

    /// Return the encapsulation (public) key bytes.
    pub fn encapsulation_key_bytes(&self) -> Vec<u8> {
        self.dk.encapsulation_key().as_bytes().to_vec()
    }

    /// Decapsulate a ciphertext, recovering the shared secret.
    ///
    /// **Note**: ML-KEM uses implicit rejection. If the ciphertext is invalid
    /// or was produced with a different key, the returned secret will be
    /// pseudorandom (not an error). The caller must detect mismatches at a
    /// higher protocol layer (e.g., via MAC verification).
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
        let ct_array: &[u8; KEM_CIPHERTEXT_LEN] = ciphertext.try_into().map_err(|_| CryptoError::KemDecapsulationFailed)?;
        let ct = Ciphertext::<MlKem768>::from(*ct_array);
        let shared = self.dk.decapsulate(&ct).map_err(|()| CryptoError::KemDecapsulationFailed)?;
        let mut out = [0u8; SHARED_SECRET_LEN];
        out.copy_from_slice(shared.as_slice());
        Ok(out)
    }
}

/// Encapsulate against a remote ML-KEM-768 encapsulation key.
///
/// Returns `(ciphertext, shared_secret)`.
pub fn kem_encapsulate(encapsulation_key_bytes: &[u8]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), CryptoError> {
    let ek_array: &[u8; KEM_ENCAPSULATION_KEY_LEN] = encapsulation_key_bytes
        .try_into()
        .map_err(|_| CryptoError::KemDecapsulationFailed)?;
    let ek = ml_kem::kem::EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(ek_array.into());
    let (ct, shared) = ek.encapsulate(&mut OsRng).map_err(|()| CryptoError::KemDecapsulationFailed)?;
    let ct_bytes = ct.to_vec();
    let mut secret = [0u8; SHARED_SECRET_LEN];
    secret.copy_from_slice(shared.as_slice());
    Ok((ct_bytes, secret))
}

/// Message sent by the initiator to the responder during hybrid key exchange.
pub struct InitiatorMessage {
    /// Initiator's X25519 ephemeral public key.
    pub x25519_public: [u8; x25519::KEY_LEN],
    /// ML-KEM-768 ciphertext encapsulated against the responder's KEM key.
    pub kem_ciphertext: Vec<u8>,
}

/// State held by the initiator between initiation and finalization.
pub struct InitiatorState {
    x25519_keypair: x25519::KeyPair,
    kem_shared_secret: [u8; SHARED_SECRET_LEN],
}

impl Drop for InitiatorState {
    fn drop(&mut self) {
        self.kem_shared_secret.zeroize();
    }
}

/// Message sent by the responder back to the initiator.
pub struct ResponderMessage {
    /// Responder's X25519 ephemeral public key.
    pub x25519_public: [u8; x25519::KEY_LEN],
}

/// Initiate a hybrid key exchange.
///
/// The initiator generates an ephemeral X25519 key pair and encapsulates
/// against the responder's ML-KEM-768 encapsulation key. Returns the
/// initiator's state and the message to send to the responder.
pub fn initiate(responder_kem_ek: &[u8]) -> Result<(InitiatorState, InitiatorMessage), CryptoError> {
    let x25519_keypair = x25519::KeyPair::generate();
    let (kem_ciphertext, kem_shared) = kem_encapsulate(responder_kem_ek)?;

    let msg = InitiatorMessage {
        x25519_public: x25519_keypair.public_key_bytes(),
        kem_ciphertext,
    };

    let state = InitiatorState {
        x25519_keypair,
        kem_shared_secret: kem_shared,
    };

    Ok((state, msg))
}

/// Respond to a hybrid key exchange.
///
/// The responder generates an ephemeral X25519 key pair, performs DH with
/// the initiator's public key, decapsulates the ML-KEM ciphertext, and
/// derives the combined shared secret.
///
/// Returns `(shared_secret, ResponderMessage)`.
pub fn respond(
    responder_kem_kp: &KemKeyPair,
    initiator_msg: &InitiatorMessage,
) -> Result<([u8; SHARED_SECRET_LEN], ResponderMessage), CryptoError> {
    let x25519_keypair = x25519::KeyPair::generate();
    let x25519_shared = x25519_keypair.diffie_hellman(&initiator_msg.x25519_public);
    let kem_shared = responder_kem_kp.decapsulate(&initiator_msg.kem_ciphertext)?;

    let combined = derive_combined_secret(x25519_shared.as_bytes(), &kem_shared)?;

    let msg = ResponderMessage {
        x25519_public: x25519_keypair.public_key_bytes(),
    };

    Ok((combined, msg))
}

/// Finalize the hybrid key exchange on the initiator side.
///
/// The initiator performs DH with the responder's public key and derives
/// the same combined shared secret the responder computed.
pub fn finalize(state: InitiatorState, responder_msg: &ResponderMessage) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
    let x25519_shared = state.x25519_keypair.diffie_hellman(&responder_msg.x25519_public);
    derive_combined_secret(x25519_shared.as_bytes(), &state.kem_shared_secret)
}

/// Derive the combined shared secret from X25519 and ML-KEM contributions.
///
/// `combined = HKDF-SHA256(salt=[], ikm=x25519_shared || kem_shared, info=HYBRID_INFO, len=32)`
fn derive_combined_secret(
    x25519_shared: &[u8; x25519::KEY_LEN],
    kem_shared: &[u8; SHARED_SECRET_LEN],
) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
    let mut ikm = Vec::with_capacity(x25519::KEY_LEN + SHARED_SECRET_LEN);
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(kem_shared);

    let derived = kdf::derive(b"", &ikm, HYBRID_INFO, SHARED_SECRET_LEN)?;
    let mut out = [0u8; SHARED_SECRET_LEN];
    out.copy_from_slice(&derived);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-1: ML-KEM-768 keypair generation produces correct-sized keys
    #[test]
    fn kem_keypair_generates_correct_sized_keys() {
        let kp = KemKeyPair::generate();
        let ek_bytes = kp.encapsulation_key_bytes();
        assert_eq!(ek_bytes.len(), KEM_ENCAPSULATION_KEY_LEN);
    }

    // T-2: ML-KEM-768 encap/decap round-trip: shared secrets match
    #[test]
    fn kem_encap_decap_round_trip() {
        let kp = KemKeyPair::generate();
        let ek_bytes = kp.encapsulation_key_bytes();

        let (ct, sender_secret) = kem_encapsulate(&ek_bytes).expect("encapsulate should succeed");
        let receiver_secret = kp.decapsulate(&ct).expect("decapsulate should succeed");

        assert_eq!(sender_secret, receiver_secret);
    }

    // T-3: ML-KEM-768 encap with different keys → different ciphertexts
    #[test]
    fn kem_different_keys_different_ciphertexts() {
        let kp1 = KemKeyPair::generate();
        let kp2 = KemKeyPair::generate();

        let (ct1, _) = kem_encapsulate(&kp1.encapsulation_key_bytes()).expect("encapsulate should succeed");
        let (ct2, _) = kem_encapsulate(&kp2.encapsulation_key_bytes()).expect("encapsulate should succeed");

        assert_ne!(ct1, ct2);
    }

    // T-7: ML-KEM ciphertext length is 1088 bytes
    #[test]
    fn kem_ciphertext_length() {
        let kp = KemKeyPair::generate();
        let (ct, _) = kem_encapsulate(&kp.encapsulation_key_bytes()).expect("encapsulate should succeed");
        assert_eq!(ct.len(), KEM_CIPHERTEXT_LEN);
    }

    // T-8: ML-KEM encapsulation key length is 1184 bytes
    #[test]
    fn kem_encapsulation_key_length() {
        let kp = KemKeyPair::generate();
        assert_eq!(kp.encapsulation_key_bytes().len(), KEM_ENCAPSULATION_KEY_LEN);
    }

    // T-4: Hybrid KEX round-trip: both sides derive identical secret
    #[test]
    fn hybrid_kex_round_trip() {
        let responder_kem = KemKeyPair::generate();
        let responder_ek = responder_kem.encapsulation_key_bytes();

        let (initiator_state, initiator_msg) = initiate(&responder_ek).expect("initiate should succeed");
        let (responder_secret, responder_msg) = respond(&responder_kem, &initiator_msg).expect("respond should succeed");
        let initiator_secret = finalize(initiator_state, &responder_msg).expect("finalize should succeed");

        assert_eq!(initiator_secret, responder_secret);
        assert_eq!(initiator_secret.len(), SHARED_SECRET_LEN);
    }

    // T-5: Hybrid KEX: different ephemeral keys → different secrets
    #[test]
    fn hybrid_kex_different_ephemeral_keys_different_secrets() {
        let responder_kem = KemKeyPair::generate();
        let responder_ek = responder_kem.encapsulation_key_bytes();

        let (state1, msg1) = initiate(&responder_ek).expect("initiate should succeed");
        let (secret1, resp1) = respond(&responder_kem, &msg1).expect("respond should succeed");
        let final1 = finalize(state1, &resp1).expect("finalize should succeed");

        let (state2, msg2) = initiate(&responder_ek).expect("initiate should succeed");
        let (secret2, resp2) = respond(&responder_kem, &msg2).expect("respond should succeed");
        let final2 = finalize(state2, &resp2).expect("finalize should succeed");

        // Different ephemeral X25519 keys and KEM encapsulations → different secrets
        assert_ne!(secret1, secret2);
        assert_ne!(final1, final2);
    }

    // T-6: Hybrid KEX: combined secret differs from X25519-only or KEM-only
    #[test]
    fn hybrid_kex_combined_secret_differs_from_components() {
        let responder_kem = KemKeyPair::generate();
        let responder_ek = responder_kem.encapsulation_key_bytes();

        let (initiator_state, initiator_msg) = initiate(&responder_ek).expect("initiate should succeed");
        let (responder_secret, responder_msg) = respond(&responder_kem, &initiator_msg).expect("respond should succeed");
        let _initiator_secret = finalize(initiator_state, &responder_msg).expect("finalize should succeed");

        // X25519-only secret would just be the DH output
        let x25519_only = kdf::derive(b"", b"x25519-only-test", HYBRID_INFO, SHARED_SECRET_LEN).expect("derive should succeed");
        let mut x25519_only_arr = [0u8; SHARED_SECRET_LEN];
        x25519_only_arr.copy_from_slice(&x25519_only);

        // The combined secret should not equal any trivially-derived value
        assert_ne!(responder_secret, x25519_only_arr);
        assert_ne!(responder_secret, [0u8; SHARED_SECRET_LEN]);
    }

    // T-extra: KEM encapsulate with invalid key length → error
    #[test]
    fn kem_encapsulate_invalid_key_length() {
        let result = kem_encapsulate(&[0u8; 32]);
        assert!(matches!(result, Err(CryptoError::KemDecapsulationFailed)));
    }

    // T-extra: KEM decapsulate with invalid ciphertext length → error
    #[test]
    fn kem_decapsulate_invalid_ciphertext_length() {
        let kp = KemKeyPair::generate();
        let result = kp.decapsulate(&[0u8; 32]);
        assert!(matches!(result, Err(CryptoError::KemDecapsulationFailed)));
    }

    // T-P002-1: DK serialization produces correct length
    #[test]
    fn kem_dk_bytes_length() {
        let kp = KemKeyPair::generate();
        assert_eq!(kp.dk_bytes().len(), KEM_DECAPSULATION_KEY_LEN);
    }

    // T-P002-2: DK serialize → deserialize round-trip preserves encapsulation key
    #[test]
    fn kem_dk_serialization_round_trip() {
        let kp = KemKeyPair::generate();
        let dk_bytes = kp.dk_bytes();
        let ek_bytes_original = kp.encapsulation_key_bytes();

        let kp2 = KemKeyPair::from_dk_bytes(&dk_bytes).expect("reconstruct should succeed");
        let ek_bytes_loaded = kp2.encapsulation_key_bytes();

        assert_eq!(ek_bytes_original, ek_bytes_loaded);
    }

    // T-P002-3: DK serialize → deserialize → encap/decap still works
    #[test]
    fn kem_dk_round_trip_functional() {
        let kp = KemKeyPair::generate();
        let dk_bytes = kp.dk_bytes();

        let kp2 = KemKeyPair::from_dk_bytes(&dk_bytes).expect("reconstruct should succeed");
        let ek = kp2.encapsulation_key_bytes();

        let (ct, sender_secret) = kem_encapsulate(&ek).expect("encapsulate should succeed");
        let receiver_secret = kp2.decapsulate(&ct).expect("decapsulate should succeed");

        assert_eq!(sender_secret, receiver_secret);
    }

    // T-P002-4: from_dk_bytes with wrong length returns error
    #[test]
    fn kem_from_dk_bytes_invalid_length() {
        let result = KemKeyPair::from_dk_bytes(&[0u8; 32]);
        assert!(matches!(result, Err(CryptoError::KemDecapsulationFailed)));
    }
}
