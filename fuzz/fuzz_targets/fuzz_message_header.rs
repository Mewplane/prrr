// FRD: specs/frds/FRD-017.md
#![no_main]
use libfuzzer_sys::fuzz_target;
use prrr::messaging::ratchet::MessageHeader;

fuzz_target!(|data: &[u8]| {
    // Fuzz MessageHeader::from_bytes with arbitrary input.
    // Must not panic — only return Ok or Err.
    let _ = MessageHeader::from_bytes(data);
});
