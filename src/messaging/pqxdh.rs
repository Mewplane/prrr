// FRD: specs/frds/FRD-014.md

//! PQXDH (Post-Quantum Extended Diffie-Hellman) key agreement protocol.
//!
//! Implements the initial key agreement between Alice (initiator) and Bob
//! (responder). Alice uses Bob's prekey bundle to derive a shared secret
//! and produce an initial message. Bob uses his private keys and the
//! initial message to derive the same shared secret.

use zeroize::Zeroize;

use crate::{
    crypto::{CryptoError, aead, hybrid_kex, kdf, x25519},
    messaging::keys::{IdentityKeyPair, OneTimePrekey, PqPrekey, PrekeyBundle, PrekeyError, SignedPrekey, X25519_PUB_LEN},
};

/// HKDF info string for PQXDH shared secret derivation.
const PQXDH_INFO: &[u8] = b"prrr-pqxdh-v1";

/// Domain separator `F` for X25519: 32 bytes of 0xFF.
const F_X25519: [u8; 32] = [0xFF; 32];

/// HKDF salt: 32 zero bytes.
const ZERO_SALT: [u8; 32] = [0u8; 32];

/// Shared secret length in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

/// AEAD nonce for the first message (counter = 0).
const INITIAL_NONCE: [u8; aead::NONCE_LEN] = [0u8; aead::NONCE_LEN];

/// Errors from PQXDH protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum PqxdhError {
    /// Prekey bundle verification failed.
    #[error(transparent)]
    PrekeyVerification(#[from] PrekeyError),

    /// Cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The initial message Alice sends to Bob after PQXDH key agreement.
pub struct InitialMessage {
    /// Alice's identity public key.
    pub ik_a: [u8; X25519_PUB_LEN],
    /// Alice's ephemeral public key.
    pub ek_a: [u8; X25519_PUB_LEN],
    /// KEM ciphertext encapsulated against Bob's PQ prekey.
    pub kem_ciphertext: Vec<u8>,
    /// SPK key identifier (so Bob knows which SPK was used).
    pub spk_id: u32,
    /// OPK key identifier (if an OPK was used).
    pub opk_id: Option<u32>,
    /// PQ prekey key identifier.
    pub pq_prekey_id: u32,
    /// AEAD-encrypted initial payload.
    pub ciphertext: Vec<u8>,
}

/// The result of a successful PQXDH session initiation.
pub struct SessionInitResult {
    /// The derived shared secret (32 bytes).
    pub shared_secret: [u8; SHARED_SECRET_LEN],
    /// The associated data used for AEAD.
    pub associated_data: Vec<u8>,
    /// The initial message to send to Bob.
    pub initial_message: InitialMessage,
}

impl Drop for SessionInitResult {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

/// Build the associated data: IK_A_pub || IK_B_pub || PQPK_B_pub.
fn build_associated_data(ik_a_pub: &[u8; X25519_PUB_LEN], ik_b_pub: &[u8; X25519_PUB_LEN], pqpk_b_pub: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(X25519_PUB_LEN + X25519_PUB_LEN + pqpk_b_pub.len());
    ad.extend_from_slice(ik_a_pub);
    ad.extend_from_slice(ik_b_pub);
    ad.extend_from_slice(pqpk_b_pub);
    ad
}

/// Derive the shared secret SK from the concatenated key material.
///
/// `ikm = F || DH1 || DH2 || DH3 [|| DH4] || SS`
fn derive_shared_secret(key_material: &[u8]) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
    let derived = kdf::derive(&ZERO_SALT, key_material, PQXDH_INFO, SHARED_SECRET_LEN)?;
    let mut sk = [0u8; SHARED_SECRET_LEN];
    sk.copy_from_slice(&derived);
    Ok(sk)
}

/// Initiate a PQXDH session (Alice's side).
///
/// Alice generates an ephemeral key, performs DH operations against Bob's
/// prekey bundle, encapsulates against Bob's PQ prekey, and derives the
/// shared secret. The `plaintext` is encrypted with the derived key.
///
/// The caller must verify the bundle before calling this function, or
/// pass Bob's identity secret bytes for verification.
pub fn initiate_session(
    alice_ik: &IdentityKeyPair,
    bob_bundle: &PrekeyBundle,
    bob_ik_secret: &[u8; x25519::KEY_LEN],
    plaintext: &[u8],
) -> Result<SessionInitResult, PqxdhError> {
    // Verify bundle signatures
    bob_bundle.verify(bob_ik_secret)?;

    // Generate ephemeral key
    let ek_a = x25519::KeyPair::generate();

    // DH1 = DH(IK_A, SPK_B)
    let dh1 = alice_ik.diffie_hellman(&bob_bundle.spk);
    // DH2 = DH(EK_A, IK_B)
    let dh2 = ek_a.diffie_hellman(&bob_bundle.identity_key);
    // DH3 = DH(EK_A, SPK_B)
    let dh3 = ek_a.diffie_hellman(&bob_bundle.spk);
    // DH4 = DH(EK_A, OPK_B) — optional
    let dh4 = bob_bundle.opk.map(|opk| ek_a.diffie_hellman(&opk));

    // KEM encapsulate against Bob's PQ prekey
    let (kem_ct, kem_ss) = hybrid_kex::kem_encapsulate(&bob_bundle.pq_prekey)?;

    // Build key material: F || DH1 || DH2 || DH3 [|| DH4] || SS
    let dh4_len = if dh4.is_some() { x25519::KEY_LEN } else { 0 };
    let ikm_len = F_X25519.len() + x25519::KEY_LEN * 3 + dh4_len + hybrid_kex::SHARED_SECRET_LEN;
    let mut ikm = Vec::with_capacity(ikm_len);
    ikm.extend_from_slice(&F_X25519);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(ref dh4_out) = dh4 {
        ikm.extend_from_slice(dh4_out.as_bytes());
    }
    ikm.extend_from_slice(&kem_ss);

    let sk = derive_shared_secret(&ikm)?;

    // Build associated data
    let ad = build_associated_data(&alice_ik.public_key_bytes(), &bob_bundle.identity_key, &bob_bundle.pq_prekey);

    // Encrypt initial plaintext
    let ciphertext = aead::encrypt(&sk, &INITIAL_NONCE, plaintext, &ad);

    Ok(SessionInitResult {
        shared_secret: sk,
        associated_data: ad,
        initial_message: InitialMessage {
            ik_a: alice_ik.public_key_bytes(),
            ek_a: ek_a.public_key_bytes(),
            kem_ciphertext: kem_ct,
            spk_id: bob_bundle.spk_id,
            opk_id: bob_bundle.opk_id,
            pq_prekey_id: bob_bundle.pq_prekey_id,
            ciphertext,
        },
    })
}

/// Respond to a PQXDH initial message (Bob's side).
///
/// Bob uses his private keys to perform the same DH operations and KEM
/// decapsulation, deriving the same shared secret Alice computed. Returns
/// the shared secret and decrypted initial plaintext.
pub fn respond_to_session(
    bob_ik: &IdentityKeyPair,
    bob_spk: &SignedPrekey,
    bob_opk: Option<&OneTimePrekey>,
    bob_pq_prekey: &PqPrekey,
    initial_msg: &InitialMessage,
) -> Result<([u8; SHARED_SECRET_LEN], Vec<u8>), PqxdhError> {
    // DH1 = DH(SPK_B, IK_A) — same shared secret as DH(IK_A, SPK_B)
    let dh1 = bob_spk.diffie_hellman(&initial_msg.ik_a);
    // DH2 = DH(IK_B, EK_A)
    let dh2 = bob_ik.diffie_hellman(&initial_msg.ek_a);
    // DH3 = DH(SPK_B, EK_A)
    let dh3 = bob_spk.diffie_hellman(&initial_msg.ek_a);
    // DH4 = DH(OPK_B, EK_A) — optional
    let dh4 = bob_opk.map(|opk| opk.diffie_hellman(&initial_msg.ek_a));

    // KEM decapsulate
    let kem_ss = bob_pq_prekey.decapsulate(&initial_msg.kem_ciphertext)?;

    // Build key material: F || DH1 || DH2 || DH3 [|| DH4] || SS
    let dh4_len = if dh4.is_some() { x25519::KEY_LEN } else { 0 };
    let ikm_len = F_X25519.len() + x25519::KEY_LEN * 3 + dh4_len + hybrid_kex::SHARED_SECRET_LEN;
    let mut ikm = Vec::with_capacity(ikm_len);
    ikm.extend_from_slice(&F_X25519);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(ref dh4_out) = dh4 {
        ikm.extend_from_slice(dh4_out.as_bytes());
    }
    ikm.extend_from_slice(&kem_ss);

    let sk = derive_shared_secret(&ikm)?;

    // Build associated data
    let ad = build_associated_data(
        &initial_msg.ik_a,
        &bob_ik.public_key_bytes(),
        &bob_pq_prekey.encapsulation_key_bytes(),
    );

    // Decrypt initial message
    let plaintext = aead::decrypt(&sk, &INITIAL_NONCE, &initial_msg.ciphertext, &ad)?;

    Ok((sk, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::keys::{IdentityKeyPair, OneTimePrekey, PqPrekey, SignedPrekey, generate_prekey_bundle};

    const TEST_PLAINTEXT: &[u8] = b"hello bob, this is alice";

    /// Helper: generate Bob's full key set and prekey bundle.
    fn bob_keys_and_bundle(with_opk: bool) -> (IdentityKeyPair, SignedPrekey, Option<OneTimePrekey>, PqPrekey, PrekeyBundle) {
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPrekey::generate(&bob_ik, 1);
        let bob_opk = if with_opk { Some(OneTimePrekey::generate(1)) } else { None };
        let bob_pq = PqPrekey::generate(&bob_ik, 1);
        let bundle = generate_prekey_bundle(&bob_ik, &bob_spk, bob_opk.as_ref(), &bob_pq);
        (bob_ik, bob_spk, bob_opk, bob_pq, bundle)
    }

    // T-1 (FRD-014): Full PQXDH round-trip with OPK and PQOPK
    #[test]
    fn full_round_trip_with_opk() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, bob_spk, bob_opk, bob_pq, bundle) = bob_keys_and_bundle(true);

        let result = initiate_session(&alice_ik, &bundle, &bob_ik.secret_key_bytes(), TEST_PLAINTEXT).expect("initiate should succeed");

        let (bob_sk, decrypted) =
            respond_to_session(&bob_ik, &bob_spk, bob_opk.as_ref(), &bob_pq, &result.initial_message).expect("respond should succeed");

        // AC-1: Both sides derive identical shared secret
        assert_eq!(result.shared_secret, bob_sk);
        // AC-7: Decrypted plaintext matches
        assert_eq!(decrypted, TEST_PLAINTEXT);
    }

    // T-2 (FRD-014): PQXDH round-trip without OPK (depleted)
    #[test]
    fn round_trip_without_opk() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, bob_spk, _, bob_pq, bundle) = bob_keys_and_bundle(false);

        let result = initiate_session(&alice_ik, &bundle, &bob_ik.secret_key_bytes(), TEST_PLAINTEXT).expect("initiate should succeed");

        let (bob_sk, decrypted) =
            respond_to_session(&bob_ik, &bob_spk, None, &bob_pq, &result.initial_message).expect("respond should succeed");

        // AC-2: Both sides agree without OPK
        assert_eq!(result.shared_secret, bob_sk);
        assert_eq!(decrypted, TEST_PLAINTEXT);
    }

    // T-8 (FRD-014): Initial message AEAD encrypt/decrypt round-trip
    #[test]
    fn aead_round_trip_with_derived_key() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, bob_spk, bob_opk, bob_pq, bundle) = bob_keys_and_bundle(true);

        let payload = b"encrypted payload for AEAD test";
        let result = initiate_session(&alice_ik, &bundle, &bob_ik.secret_key_bytes(), payload).expect("initiate should succeed");

        let (_, decrypted) =
            respond_to_session(&bob_ik, &bob_spk, bob_opk.as_ref(), &bob_pq, &result.initial_message).expect("respond should succeed");

        assert_eq!(decrypted, payload);
    }

    // T-6 (FRD-014): Wrong identity key → different shared secret (AEAD failure)
    #[test]
    fn wrong_identity_key_aead_failure() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, bob_spk, bob_opk, bob_pq, bundle) = bob_keys_and_bundle(true);

        let result = initiate_session(&alice_ik, &bundle, &bob_ik.secret_key_bytes(), TEST_PLAINTEXT).expect("initiate should succeed");

        // Bob responds with a *different* identity key
        let wrong_bob_ik = IdentityKeyPair::generate();
        let respond_result = respond_to_session(&wrong_bob_ik, &bob_spk, bob_opk.as_ref(), &bob_pq, &result.initial_message);

        // DH2 will differ → different SK → AEAD decryption fails
        assert!(respond_result.is_err());
    }

    // T-7 (FRD-014): Tampered KEM ciphertext → different shared secret
    #[test]
    fn tampered_kem_ciphertext_aead_failure() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, bob_spk, bob_opk, bob_pq, bundle) = bob_keys_and_bundle(true);

        let result = initiate_session(&alice_ik, &bundle, &bob_ik.secret_key_bytes(), TEST_PLAINTEXT).expect("initiate should succeed");

        // Tamper with the KEM ciphertext
        let mut tampered_msg = InitialMessage {
            ik_a: result.initial_message.ik_a,
            ek_a: result.initial_message.ek_a,
            kem_ciphertext: result.initial_message.kem_ciphertext.clone(),
            spk_id: result.initial_message.spk_id,
            opk_id: result.initial_message.opk_id,
            pq_prekey_id: result.initial_message.pq_prekey_id,
            ciphertext: result.initial_message.ciphertext.clone(),
        };
        tampered_msg.kem_ciphertext[0] ^= 0xff;

        // ML-KEM implicit rejection → pseudorandom secret → AEAD fails
        let respond_result = respond_to_session(&bob_ik, &bob_spk, bob_opk.as_ref(), &bob_pq, &tampered_msg);
        assert!(respond_result.is_err());
    }

    // T-11 (FRD-014): Multiple sessions with same bundle produce different secrets
    #[test]
    fn multiple_sessions_different_secrets() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, _, _, _, bundle) = bob_keys_and_bundle(true);

        let result1 =
            initiate_session(&alice_ik, &bundle, &bob_ik.secret_key_bytes(), TEST_PLAINTEXT).expect("first initiate should succeed");

        let result2 =
            initiate_session(&alice_ik, &bundle, &bob_ik.secret_key_bytes(), TEST_PLAINTEXT).expect("second initiate should succeed");

        // Different ephemeral keys and KEM encapsulations → different secrets
        assert_ne!(result1.shared_secret, result2.shared_secret);
    }

    // T-12 (FRD-014): Bundle without OPK and minimal PQ prekey
    #[test]
    fn minimal_bundle_round_trip() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, bob_spk, _, bob_pq, bundle) = bob_keys_and_bundle(false);

        assert!(bundle.opk.is_none());

        let result = initiate_session(&alice_ik, &bundle, &bob_ik.secret_key_bytes(), TEST_PLAINTEXT).expect("initiate should succeed");

        let (bob_sk, decrypted) =
            respond_to_session(&bob_ik, &bob_spk, None, &bob_pq, &result.initial_message).expect("respond should succeed");

        assert_eq!(result.shared_secret, bob_sk);
        assert_eq!(decrypted, TEST_PLAINTEXT);
    }

    // T-extra: Associated data has correct structure
    #[test]
    fn associated_data_structure() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, _, _, _, bundle) = bob_keys_and_bundle(true);

        let result = initiate_session(&alice_ik, &bundle, &bob_ik.secret_key_bytes(), TEST_PLAINTEXT).expect("initiate should succeed");

        // AD = IK_A(32) || IK_B(32) || PQPK_B(1184)
        let expected_ad_len = X25519_PUB_LEN + X25519_PUB_LEN + hybrid_kex::KEM_ENCAPSULATION_KEY_LEN;
        assert_eq!(result.associated_data.len(), expected_ad_len);

        // First 32 bytes = Alice's IK
        assert_eq!(&result.associated_data[..X25519_PUB_LEN], &alice_ik.public_key_bytes());
        // Next 32 bytes = Bob's IK
        assert_eq!(&result.associated_data[X25519_PUB_LEN..X25519_PUB_LEN * 2], &bundle.identity_key);
    }

    // T-extra: Shared secret is 32 bytes and non-zero
    #[test]
    fn shared_secret_length_and_nonzero() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, _, _, _, bundle) = bob_keys_and_bundle(true);

        let result = initiate_session(&alice_ik, &bundle, &bob_ik.secret_key_bytes(), TEST_PLAINTEXT).expect("initiate should succeed");

        assert_eq!(result.shared_secret.len(), SHARED_SECRET_LEN);
        assert_ne!(result.shared_secret, [0u8; SHARED_SECRET_LEN]);
    }
}
