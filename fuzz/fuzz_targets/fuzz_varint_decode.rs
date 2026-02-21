// FRD: specs/frds/FRD-017.md
#![no_main]
use libfuzzer_sys::fuzz_target;
use prrr::transport::masque;

fuzz_target!(|data: &[u8]| {
    // Fuzz QUIC varint decoding with arbitrary bytes.
    // Must not panic — only return Ok or Err.
    let _ = masque::varint_decode(data);
});
