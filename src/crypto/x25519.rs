// FRD: specs/frds/FRD-001.md

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroize;

/// Byte length of an X25519 key (public or private).
pub const KEY_LEN: usize = 32;

/// An X25519 key pair for Diffie-Hellman key exchange.
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new random X25519 key pair from the OS CSPRNG.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Return the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; KEY_LEN] {
        self.public.to_bytes()
    }

    /// Return the secret (private) key bytes.
    ///
    /// Required by PQXDH prekey signing (keyed BLAKE2s MAC with identity
    /// key as the MAC key).
    pub fn secret_key_bytes(&self) -> [u8; KEY_LEN] {
        self.secret.to_bytes()
    }

    /// Perform Diffie-Hellman with the given remote public key, returning
    /// the shared secret.
    pub fn diffie_hellman(&self, their_public: &[u8; KEY_LEN]) -> DhOutput {
        let their_pk = PublicKey::from(*their_public);
        let shared = self.secret.diffie_hellman(&their_pk);
        DhOutput { shared }
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.public = PublicKey::from([0u8; KEY_LEN]);
    }
}

/// The output of a Diffie-Hellman key exchange.
pub struct DhOutput {
    shared: SharedSecret,
}

impl DhOutput {
    /// Return the raw shared secret bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.shared.as_bytes()
    }

    /// Consume the output and return the raw shared secret bytes.
    pub fn to_bytes(self) -> [u8; KEY_LEN] {
        let mut out = *self.shared.as_bytes();
        let result = out;
        out.zeroize();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-1: X25519 keypair generation produces 32-byte keys
    #[test]
    fn keypair_generates_32_byte_keys() {
        let kp = KeyPair::generate();
        let pub_bytes = kp.public_key_bytes();
        assert_eq!(pub_bytes.len(), KEY_LEN);
        // Public key must not be all zeros
        assert_ne!(pub_bytes, [0u8; KEY_LEN]);
    }

    // T-2: X25519 DH: both sides derive identical shared secret
    #[test]
    fn dh_both_sides_agree() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_shared = alice.diffie_hellman(&bob.public_key_bytes());
        let bob_shared = bob.diffie_hellman(&alice.public_key_bytes());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    // T-extra: secret_key_bytes returns 32 non-zero bytes
    #[test]
    fn secret_key_bytes_returns_32_bytes() {
        let kp = KeyPair::generate();
        let sk = kp.secret_key_bytes();
        assert_eq!(sk.len(), KEY_LEN);
        assert_ne!(sk, [0u8; KEY_LEN]);
    }

    // T-3: X25519 DH: different keypairs produce different secrets
    #[test]
    fn dh_different_keypairs_different_secrets() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let carol = KeyPair::generate();

        let ab = alice.diffie_hellman(&bob.public_key_bytes());
        let ac = alice.diffie_hellman(&carol.public_key_bytes());

        assert_ne!(ab.as_bytes(), ac.as_bytes());
    }
}
