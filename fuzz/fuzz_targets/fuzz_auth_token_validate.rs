// FRD: specs/frds/FRD-017.md
#![no_main]
use libfuzzer_sys::fuzz_target;
use prrr::obfuscation::probe_resist::AuthToken;

fuzz_target!(|data: &[u8]| {
    // Fuzz AuthToken::validate with arbitrary token bytes.
    // Uses a fixed PSK and timestamp — we care about parser robustness.
    let psk = [0x42u8; 32];
    let server_time: u64 = 1_000_000;
    let _ = AuthToken::validate(&psk, data, server_time);
});
