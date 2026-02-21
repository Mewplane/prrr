// FRD: specs/frds/FRD-017.md
#![no_main]
use libfuzzer_sys::fuzz_target;
use prrr::crypto::aead;

fuzz_target!(|data: &[u8]| {
    // Fuzz AEAD decryption with arbitrary ciphertext.
    // Uses fixed key and nonce — we care about parser robustness.
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let aad = b"fuzz-aad";
    let _ = aead::decrypt(&key, &nonce, data, aad);
});
