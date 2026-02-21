// FRD: specs/frds/FRD-014.md

//! Key types and prekey bundle for the PQXDH protocol.
//!
//! Provides identity key pairs, signed prekeys, one-time prekeys, and
//! prekey bundles used in the PQXDH key agreement.

use subtle::ConstantTimeEq;

use crate::crypto::{hybrid_kex, x25519};

/// Domain separator for prekey signatures.
const PREKEY_SIG_DOMAIN: &[u8] = b"prrr-prekey-sig-v1";

/// Byte length of a prekey signature (BLAKE2s-256 output).
pub const SIGNATURE_LEN: usize = 32;

/// Byte length of an X25519 public key.
pub const X25519_PUB_LEN: usize = x25519::KEY_LEN;

/// Byte length of an ML-KEM-768 encapsulation key.
pub const KEM_PUB_LEN: usize = hybrid_kex::KEM_ENCAPSULATION_KEY_LEN;

/// Errors from prekey bundle operations.
#[derive(Debug, thiserror::Error)]
pub enum PrekeyError {
    /// Signed prekey signature verification failed.
    #[error("invalid signed prekey signature")]
    InvalidSpkSignature,

    /// PQ prekey signature verification failed.
    #[error("invalid PQ prekey signature")]
    InvalidPqSignature,
}

/// Compute a keyed BLAKE2s MAC binding a prekey to an identity key.
///
/// `sig = BLAKE3-keyed(key=ik_secret, data=PREKEY_SIG_DOMAIN || prekey_pub)`
fn sign_prekey(ik_secret: &[u8; x25519::KEY_LEN], prekey_pub: &[u8]) -> [u8; SIGNATURE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(ik_secret);
    hasher.update(PREKEY_SIG_DOMAIN);
    hasher.update(prekey_pub);
    *hasher.finalize().as_bytes()
}

/// Verify a prekey signature in constant time.
fn verify_prekey_signature(ik_secret: &[u8; x25519::KEY_LEN], prekey_pub: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
    let expected = sign_prekey(ik_secret, prekey_pub);
    expected.ct_eq(signature).into()
}

/// An X25519 identity key pair with signing capability.
pub struct IdentityKeyPair {
    inner: x25519::KeyPair,
}

impl IdentityKeyPair {
    /// Generate a new random identity key pair.
    pub fn generate() -> Self {
        Self {
            inner: x25519::KeyPair::generate(),
        }
    }

    /// Return the public identity key bytes.
    pub fn public_key_bytes(&self) -> [u8; X25519_PUB_LEN] {
        self.inner.public_key_bytes()
    }

    /// Return the secret identity key bytes.
    pub fn secret_key_bytes(&self) -> [u8; X25519_PUB_LEN] {
        self.inner.secret_key_bytes()
    }

    /// Sign a prekey's public bytes, producing a keyed MAC.
    pub fn sign_prekey(&self, prekey_pub: &[u8]) -> [u8; SIGNATURE_LEN] {
        sign_prekey(&self.inner.secret_key_bytes(), prekey_pub)
    }

    /// Perform Diffie-Hellman with a remote public key.
    pub fn diffie_hellman(&self, their_public: &[u8; X25519_PUB_LEN]) -> x25519::DhOutput {
        self.inner.diffie_hellman(their_public)
    }
}

/// A signed X25519 prekey (SPK) bound to an identity key via keyed MAC.
pub struct SignedPrekey {
    inner: x25519::KeyPair,
    signature: [u8; SIGNATURE_LEN],
    id: u32,
}

impl SignedPrekey {
    /// Generate a new signed prekey, signed by the given identity key.
    pub fn generate(identity: &IdentityKeyPair, id: u32) -> Self {
        let inner = x25519::KeyPair::generate();
        let signature = identity.sign_prekey(&inner.public_key_bytes());
        Self { inner, signature, id }
    }

    /// Return the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; X25519_PUB_LEN] {
        self.inner.public_key_bytes()
    }

    /// Return the signature bytes.
    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// Return the key identifier.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Perform Diffie-Hellman with a remote public key.
    pub fn diffie_hellman(&self, their_public: &[u8; X25519_PUB_LEN]) -> x25519::DhOutput {
        self.inner.diffie_hellman(their_public)
    }
}

/// A one-time X25519 prekey (OPK), unsigned and single-use.
pub struct OneTimePrekey {
    inner: x25519::KeyPair,
    id: u32,
}

impl OneTimePrekey {
    /// Generate a new one-time prekey.
    pub fn generate(id: u32) -> Self {
        Self {
            inner: x25519::KeyPair::generate(),
            id,
        }
    }

    /// Return the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; X25519_PUB_LEN] {
        self.inner.public_key_bytes()
    }

    /// Return the key identifier.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Perform Diffie-Hellman with a remote public key.
    pub fn diffie_hellman(&self, their_public: &[u8; X25519_PUB_LEN]) -> x25519::DhOutput {
        self.inner.diffie_hellman(their_public)
    }
}

/// A PQ prekey (ML-KEM-768) signed by the identity key.
pub struct PqPrekey {
    inner: hybrid_kex::KemKeyPair,
    signature: [u8; SIGNATURE_LEN],
    id: u32,
}

impl PqPrekey {
    /// Generate a new PQ prekey, signed by the given identity key.
    pub fn generate(identity: &IdentityKeyPair, id: u32) -> Self {
        let inner = hybrid_kex::KemKeyPair::generate();
        let signature = identity.sign_prekey(&inner.encapsulation_key_bytes());
        Self { inner, signature, id }
    }

    /// Return the encapsulation (public) key bytes.
    pub fn encapsulation_key_bytes(&self) -> Vec<u8> {
        self.inner.encapsulation_key_bytes()
    }

    /// Return the signature bytes.
    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// Return the key identifier.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Decapsulate a ciphertext, recovering the KEM shared secret.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; hybrid_kex::SHARED_SECRET_LEN], crate::crypto::CryptoError> {
        self.inner.decapsulate(ciphertext)
    }
}

/// A prekey bundle that Bob publishes for Alice to initiate a session.
pub struct PrekeyBundle {
    /// Bob's identity public key.
    pub identity_key: [u8; X25519_PUB_LEN],
    /// Bob's signed prekey public key.
    pub spk: [u8; X25519_PUB_LEN],
    /// Signature over SPK by identity key.
    pub spk_signature: [u8; SIGNATURE_LEN],
    /// SPK key identifier.
    pub spk_id: u32,
    /// Bob's one-time prekey public key (optional — may be depleted).
    pub opk: Option<[u8; X25519_PUB_LEN]>,
    /// OPK key identifier.
    pub opk_id: Option<u32>,
    /// PQ prekey encapsulation key bytes.
    pub pq_prekey: Vec<u8>,
    /// Signature over PQ prekey by identity key.
    pub pq_signature: [u8; SIGNATURE_LEN],
    /// PQ prekey key identifier.
    pub pq_prekey_id: u32,
}

impl PrekeyBundle {
    /// Verify the signatures in this bundle using the verifier's copy of
    /// the identity secret key.
    ///
    /// In PRRR's single-server model the verifier (Alice) trusts the
    /// server delivery and uses the identity *secret* bytes to verify the
    /// keyed MAC. See FRD-014 for the rationale on keyed MAC vs XEdDSA.
    pub fn verify(&self, ik_secret: &[u8; x25519::KEY_LEN]) -> Result<(), PrekeyError> {
        if !verify_prekey_signature(ik_secret, &self.spk, &self.spk_signature) {
            return Err(PrekeyError::InvalidSpkSignature);
        }
        if !verify_prekey_signature(ik_secret, &self.pq_prekey, &self.pq_signature) {
            return Err(PrekeyError::InvalidPqSignature);
        }
        Ok(())
    }
}

/// Generate a complete prekey bundle from Bob's key material.
pub fn generate_prekey_bundle(
    identity: &IdentityKeyPair,
    spk: &SignedPrekey,
    opk: Option<&OneTimePrekey>,
    pq_prekey: &PqPrekey,
) -> PrekeyBundle {
    PrekeyBundle {
        identity_key: identity.public_key_bytes(),
        spk: spk.public_key_bytes(),
        spk_signature: *spk.signature(),
        spk_id: spk.id(),
        opk: opk.map(OneTimePrekey::public_key_bytes),
        opk_id: opk.map(OneTimePrekey::id),
        pq_prekey: pq_prekey.encapsulation_key_bytes(),
        pq_signature: *pq_prekey.signature(),
        pq_prekey_id: pq_prekey.id(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-9 (FRD-014): Bundle generation produces valid signatures
    #[test]
    fn bundle_generation_produces_valid_signatures() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPrekey::generate(&identity, 1);
        let pq_prekey = PqPrekey::generate(&identity, 1);
        let opk = OneTimePrekey::generate(1);

        let bundle = generate_prekey_bundle(&identity, &spk, Some(&opk), &pq_prekey);

        // Verify with the correct identity secret key
        assert!(bundle.verify(&identity.secret_key_bytes()).is_ok());
    }

    // T-4 (FRD-014): Invalid SPK signature rejected
    #[test]
    fn invalid_spk_signature_rejected() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPrekey::generate(&identity, 1);
        let pq_prekey = PqPrekey::generate(&identity, 1);

        let mut bundle = generate_prekey_bundle(&identity, &spk, None, &pq_prekey);
        // Tamper with the SPK signature
        bundle.spk_signature[0] ^= 0xff;

        let result = bundle.verify(&identity.secret_key_bytes());
        assert!(matches!(result, Err(PrekeyError::InvalidSpkSignature)));
    }

    // T-5 (FRD-014): Invalid PQ prekey signature rejected
    #[test]
    fn invalid_pq_signature_rejected() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPrekey::generate(&identity, 1);
        let pq_prekey = PqPrekey::generate(&identity, 1);

        let mut bundle = generate_prekey_bundle(&identity, &spk, None, &pq_prekey);
        // Tamper with the PQ signature
        bundle.pq_signature[0] ^= 0xff;

        let result = bundle.verify(&identity.secret_key_bytes());
        assert!(matches!(result, Err(PrekeyError::InvalidPqSignature)));
    }

    // T-extra: Wrong identity key fails verification
    #[test]
    fn wrong_identity_key_fails_verification() {
        let identity = IdentityKeyPair::generate();
        let wrong_identity = IdentityKeyPair::generate();
        let spk = SignedPrekey::generate(&identity, 1);
        let pq_prekey = PqPrekey::generate(&identity, 1);

        let bundle = generate_prekey_bundle(&identity, &spk, None, &pq_prekey);

        // Verify with wrong identity key should fail
        let result = bundle.verify(&wrong_identity.secret_key_bytes());
        assert!(result.is_err());
    }

    // T-extra: Bundle without OPK still valid
    #[test]
    fn bundle_without_opk_valid() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPrekey::generate(&identity, 1);
        let pq_prekey = PqPrekey::generate(&identity, 1);

        let bundle = generate_prekey_bundle(&identity, &spk, None, &pq_prekey);

        assert!(bundle.opk.is_none());
        assert!(bundle.opk_id.is_none());
        assert!(bundle.verify(&identity.secret_key_bytes()).is_ok());
    }

    // T-extra: Key IDs are preserved in bundle
    #[test]
    fn key_ids_preserved_in_bundle() {
        let identity = IdentityKeyPair::generate();
        let spk_id = 42;
        let opk_id = 99;
        let pq_id = 7;

        let spk = SignedPrekey::generate(&identity, spk_id);
        let opk = OneTimePrekey::generate(opk_id);
        let pq_prekey = PqPrekey::generate(&identity, pq_id);

        let bundle = generate_prekey_bundle(&identity, &spk, Some(&opk), &pq_prekey);

        assert_eq!(bundle.spk_id, spk_id);
        assert_eq!(bundle.opk_id, Some(opk_id));
        assert_eq!(bundle.pq_prekey_id, pq_id);
    }

    // T-extra: PQ prekey encapsulation key has correct length
    #[test]
    fn pq_prekey_encapsulation_key_length() {
        let identity = IdentityKeyPair::generate();
        let pq_prekey = PqPrekey::generate(&identity, 1);

        assert_eq!(pq_prekey.encapsulation_key_bytes().len(), KEM_PUB_LEN);
    }

    // T-extra: sign_prekey is deterministic
    #[test]
    fn sign_prekey_deterministic() {
        let identity = IdentityKeyPair::generate();
        let prekey_pub = [0xABu8; X25519_PUB_LEN];

        let sig1 = identity.sign_prekey(&prekey_pub);
        let sig2 = identity.sign_prekey(&prekey_pub);

        assert_eq!(sig1, sig2);
    }

    // T-extra: Different prekey → different signature
    #[test]
    fn different_prekey_different_signature() {
        let identity = IdentityKeyPair::generate();
        let prekey_pub_a = [0xAAu8; X25519_PUB_LEN];
        let prekey_pub_b = [0xBBu8; X25519_PUB_LEN];

        let sig_a = identity.sign_prekey(&prekey_pub_a);
        let sig_b = identity.sign_prekey(&prekey_pub_b);

        assert_ne!(sig_a, sig_b);
    }
}
