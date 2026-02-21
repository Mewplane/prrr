// FRD: specs/frds/FRD-017.md
#![no_main]
use libfuzzer_sys::fuzz_target;
use prrr::transport::encrypted_channel::EncryptedChannel;

fuzz_target!(|data: &[u8]| {
    // Fuzz EncryptedChannel::recv with arbitrary wire bytes.
    // Uses fixed test keys — we only care about parser robustness.
    let mut channel = EncryptedChannel::new([0x42; 32], [0x43; 32]);
    let _ = channel.recv(data);
});
