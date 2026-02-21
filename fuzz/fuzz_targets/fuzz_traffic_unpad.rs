// FRD: specs/frds/FRD-017.md
#![no_main]
use libfuzzer_sys::fuzz_target;
use prrr::obfuscation::traffic_morph;

fuzz_target!(|data: &[u8]| {
    // Fuzz traffic morph unpadding with arbitrary framed bytes.
    // Must not panic — only return Ok or Err.
    let _ = traffic_morph::unpad(data);
});
