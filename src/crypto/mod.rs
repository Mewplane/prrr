/// AEAD encryption/decryption (ChaCha20-Poly1305).
pub mod aead;
/// Hybrid X25519 + ML-KEM-768 post-quantum key exchange.
pub mod hybrid_kex;
/// HKDF-SHA256 key derivation and BLAKE2s hashing.
pub mod kdf;
/// X25519 Diffie-Hellman key exchange.
pub mod x25519;

/// Errors produced by cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// AEAD decryption or authentication failed.
    #[error("AEAD decryption failed")]
    AeadDecryptFailed,

    /// HKDF output length is invalid (exceeds 255 * HashLen).
    #[error("HKDF invalid output length")]
    HkdfInvalidLength,

    /// ML-KEM decapsulation failed.
    #[error("KEM decapsulation failed")]
    KemDecapsulationFailed,
}
