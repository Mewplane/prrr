// FRD: specs/frds/FRD-017.md
#![no_main]
use libfuzzer_sys::fuzz_target;
use prrr::messaging::types::EncryptedEnvelope;

fuzz_target!(|data: &[u8]| {
    // Fuzz EncryptedEnvelope::from_bytes with arbitrary input.
    // Must not panic — only return Ok or Err.
    let _ = EncryptedEnvelope::from_bytes(data);
});
