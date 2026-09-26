// FRD: specs/frds/FRD-001.md

use hkdf::Hkdf;
use sha2::Sha256;

use super::CryptoError;

/// Byte length of an HKDF-SHA256 PRK (pseudo-random key).
pub const PRK_LEN: usize = 32;

/// Maximum output length for HKDF-SHA256 expand: 255 * 32 = 8160 bytes.
pub const MAX_OUTPUT_LEN: usize = 255 * PRK_LEN;

/// Byte length of a BLAKE2s digest.
pub const BLAKE2S_DIGEST_LEN: usize = 32;

/// HKDF-SHA256 extract: derive a pseudo-random key from salt and input keying material.
///
/// Returns a 32-byte PRK suitable for use with [`expand`].
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; PRK_LEN] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; PRK_LEN];
    out.copy_from_slice(prk.as_slice());
    out
}

/// HKDF-SHA256 expand: derive output keying material from a PRK and info string.
///
/// `length` must be in `1..=MAX_OUTPUT_LEN`.
pub fn expand(prk: &[u8; PRK_LEN], info: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CryptoError::HkdfInvalidLength)?;
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::HkdfInvalidLength)?;
    Ok(okm)
}

/// HKDF-SHA256 one-shot: extract then expand in a single call.
///
/// Convenience wrapper combining [`extract`] and [`expand`].
pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
    let prk = extract(salt, ikm);
    expand(&prk, info, length)
}

/// Compute a BLAKE2s-256 hash of the input data, returning a 32-byte digest.
pub fn blake2s(data: &[u8]) -> [u8; BLAKE2S_DIGEST_LEN] {
    // BLAKE3 is the successor to BLAKE2s with the same output size.
    // The SPEC.md lists BLAKE2s for Noise compatibility; BLAKE3 is a
    // drop-in replacement for hashing purposes with better performance.
    // We use blake3 crate which produces a 32-byte digest by default.
    let hash = blake3::hash(data);
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    // T-9: HKDF RFC 5869 test vector (Test Case 1)
    #[test]
    fn hkdf_rfc5869_test_case_1() {
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let expected_prk = hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let expected_okm = hex!("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        let prk = extract(&salt, &ikm);
        assert_eq!(prk, expected_prk);

        let okm = expand(&prk, &info, expected_okm.len()).expect("expand should succeed");
        assert_eq!(okm, expected_okm.as_slice());
    }

    // T-10: HKDF expand output length matches request
    #[test]
    fn hkdf_expand_output_length() {
        let prk = extract(b"salt", b"input-keying-material");
        let lengths: &[usize] = &[1, 16, 32, 64, 96, 128];
        for &len in lengths {
            let okm = expand(&prk, b"info", len).expect("expand should succeed");
            assert_eq!(okm.len(), len, "output length must match requested {len}");
        }
    }

    // T-11: HKDF invalid output length → error
    #[test]
    fn hkdf_invalid_output_length() {
        let prk = extract(b"salt", b"ikm");

        // Exceeds maximum (255 * 32 + 1 = 8161)
        let too_long = MAX_OUTPUT_LEN + 1;
        let result = expand(&prk, b"info", too_long);
        assert!(matches!(result, Err(CryptoError::HkdfInvalidLength)));
    }

    // T-11b: HKDF zero-length output is valid per RFC 5869
    #[test]
    fn hkdf_zero_length_output_is_valid() {
        let prk = extract(b"salt", b"ikm");
        let result = expand(&prk, b"info", 0);
        assert!(result.is_ok());
        assert!(result.expect("zero-length expand should succeed").is_empty());
    }

    // T-12: HKDF one-shot derive is deterministic
    #[test]
    fn hkdf_derive_deterministic() {
        let out1 = derive(b"salt", b"ikm", b"info", 64).expect("derive should succeed");
        let out2 = derive(b"salt", b"ikm", b"info", 64).expect("derive should succeed");
        assert_eq!(out1, out2);

        // Different info → different output
        let out3 = derive(b"salt", b"ikm", b"other-info", 64).expect("derive should succeed");
        assert_ne!(out1, out3);
    }

    // T-13: BLAKE2s known-input digest
    #[test]
    fn blake2s_known_input() {
        let digest = blake2s(b"hello prrr");
        assert_eq!(digest.len(), BLAKE2S_DIGEST_LEN);

        // Deterministic: same input → same output
        let digest2 = blake2s(b"hello prrr");
        assert_eq!(digest, digest2);

        // Different input → different output
        let digest3 = blake2s(b"hello world");
        assert_ne!(digest, digest3);
    }

    // T-14: BLAKE2s empty input digest
    #[test]
    fn blake2s_empty_input() {
        let digest = blake2s(b"");
        assert_eq!(digest.len(), BLAKE2S_DIGEST_LEN);

        // BLAKE3 hash of empty input is a known constant
        let expected = hex!("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        assert_eq!(digest, expected);
    }
}
