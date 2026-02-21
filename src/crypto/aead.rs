// FRD: specs/frds/FRD-001.md

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use super::CryptoError;

/// Byte length of a ChaCha20-Poly1305 key.
pub const KEY_LEN: usize = 32;

/// Byte length of a ChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 12;

/// Byte length of the Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;

/// Encrypt `plaintext` with ChaCha20-Poly1305.
///
/// Returns ciphertext (plaintext.len() + TAG_LEN bytes).
///
/// # Warning
/// Nonce **must never** be reused with the same key. Callers are responsible
/// for monotonic nonce management (see F-005).
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .expect("ChaCha20-Poly1305 encryption should never fail")
}

/// Decrypt `ciphertext` with ChaCha20-Poly1305.
///
/// `ciphertext` must include the 16-byte authentication tag appended
/// by `encrypt`. Returns the original plaintext on success.
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::AeadDecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const TEST_KEY: [u8; KEY_LEN] = hex!("0000000000000000000000000000000000000000000000000000000000000001");
    const TEST_NONCE: [u8; NONCE_LEN] = hex!("000000000000000000000002");
    const TEST_AAD: &[u8] = b"prrr-test";
    const TEST_PLAINTEXT: &[u8] = b"hello prrr protocol";

    // T-4: AEAD encrypt/decrypt round-trip
    #[test]
    fn encrypt_decrypt_round_trip() {
        let ciphertext = encrypt(&TEST_KEY, &TEST_NONCE, TEST_PLAINTEXT, TEST_AAD);
        let decrypted = decrypt(&TEST_KEY, &TEST_NONCE, &ciphertext, TEST_AAD).expect("decryption should succeed");
        assert_eq!(decrypted, TEST_PLAINTEXT);
    }

    // T-5: AEAD RFC 8439 test vector
    #[test]
    fn rfc8439_test_vector() {
        // RFC 8439 Section 2.8.2
        let key = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex!("070000004041424344454647");
        let aad = hex!("50515253c0c1c2c3c4c5c6c7");
        let plaintext =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_ciphertext = hex!(
            "d31a8d34648e60db7b86afbc53ef7ec2"
            "a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b"
            "1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58"
            "fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b"
            "6116"
            "1ae10b594f09e26a7e902ecbd0600691"
        );

        let ciphertext = encrypt(&key, &nonce, plaintext, &aad);
        assert_eq!(ciphertext, expected_ciphertext.as_slice());

        let decrypted = decrypt(&key, &nonce, &ciphertext, &aad).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    // T-6: AEAD tampered ciphertext → error
    #[test]
    fn tampered_ciphertext_fails() {
        let mut ciphertext = encrypt(&TEST_KEY, &TEST_NONCE, TEST_PLAINTEXT, TEST_AAD);
        // Flip one byte in the ciphertext body
        ciphertext[0] ^= 0xff;

        let result = decrypt(&TEST_KEY, &TEST_NONCE, &ciphertext, TEST_AAD);
        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    // T-7: AEAD wrong key → error
    #[test]
    fn wrong_key_fails() {
        let ciphertext = encrypt(&TEST_KEY, &TEST_NONCE, TEST_PLAINTEXT, TEST_AAD);

        let wrong_key = hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let result = decrypt(&wrong_key, &TEST_NONCE, &ciphertext, TEST_AAD);
        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    // T-8: AEAD wrong AAD → error
    #[test]
    fn wrong_aad_fails() {
        let ciphertext = encrypt(&TEST_KEY, &TEST_NONCE, TEST_PLAINTEXT, TEST_AAD);

        let result = decrypt(&TEST_KEY, &TEST_NONCE, &ciphertext, b"wrong-aad");
        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }
}
